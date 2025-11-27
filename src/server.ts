import "dotenv/config";
import express from "express";
import path from "path";
import cookieParser from "cookie-parser";
import cors from "cors";
import bcrypt from "bcrypt";
import expressLayouts from "express-ejs-layouts";
import { db } from "./db";
import {
  creators,
  students,
  courses,
  questions,
  options,
  exams,
  answers,
  transactions,
  certificates,
  courseVideos,
  progress,
} from "./schema";
import { eq, and, or, like } from "drizzle-orm";
import { requireCreator, signToken } from "./auth";
import PDFDocument from "pdfkit";
import QRCode from "qrcode";
import fs from "fs";
import Stripe from "stripe";

const stripeSecret = process.env.STRIPE_SECRET || "";
const stripe = stripeSecret ? new Stripe(stripeSecret) : null;

const app = express();
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
// Expor usuário autenticado (aluno/criador) para as views
import { verifyToken } from "./auth";
app.use((req, res, next) => {
  const student = verifyToken((req as any).cookies?.student_token);
  const creator = verifyToken((req as any).cookies?.creator_token);
  (res as any).locals.student = student && student.role === 'student' ? student : null;
  (res as any).locals.creator = creator && creator.role === 'creator' ? creator : null;
  next();
});
app.set("view engine", "ejs");
app.set("views", path.join(process.cwd(), "views"));
app.use(expressLayouts);
app.set("layout", "layout");
app.use("/public", express.static(path.join(process.cwd(), "public")));
app.use("/certificados", express.static(path.join(process.cwd(), "certificados")));

// Helpers
function ensureDirs() {
  const certDir = path.join(process.cwd(), "certificados");
  if (!fs.existsSync(certDir)) fs.mkdirSync(certDir);
}
ensureDirs();

// UI routes
app.get("/", async (req, res) => {
  const q = String((req.query.q as string) || '').trim();
  let allCourses;
  if (q) {
    const pattern = `%${q}%`;
    allCourses = await db.select().from(courses).where(
      or(like(courses.title, pattern), like(courses.description, pattern), like(courses.slug, pattern))
    );
  } else {
    allCourses = await db.select().from(courses);
  }
  res.render("index", { courses: allCourses, q });
});

app.get("/course/:id", async (req, res) => {
  const id = Number(req.params.id);
  const course = (await db.select().from(courses).where(eq(courses.id, id)))[0];
  if (!course) return res.status(404).send("Curso não encontrado");
  // ensure session cookie
  const cookies = (req as any).cookies || {};
  let sessionId = cookies["cp_session"];
  if (!sessionId) {
    sessionId = Math.random().toString(36).slice(2) + Date.now();
    res.cookie("cp_session", sessionId, { httpOnly: false });
  }
  const vids = await db.select().from(courseVideos).where(eq(courseVideos.courseId, id));
  const prog = await db.select().from(progress).where(and(eq(progress.courseId, id), eq(progress.sessionId, sessionId)));
  const completedIds = new Set(prog.filter(p => p.completed as unknown as number === 1).map(p => p.videoId as string));
  res.render("course", { course, sessionId, videos: vids, completedIds });
});

// Save playlist items (from client)
app.post("/course/:id/playlist", async (req, res) => {
  const id = Number(req.params.id);
  const { videoIds } = req.body as { videoIds: string[] };
  if (!Array.isArray(videoIds) || videoIds.length === 0) return res.status(400).json({ error: "Lista vazia" });
  // Replace existing
  await db.delete(courseVideos).where(eq(courseVideos.courseId, id));
  for (const [i, v] of videoIds.entries()) {
    await db.insert(courseVideos).values({ courseId: id, videoId: v, position: i });
  }
  res.json({ ok: true, count: videoIds.length });
});

// Save progress per video
app.post("/course/:id/progress", async (req, res) => {
  const id = Number(req.params.id);
  const { sessionId, videoId, watchedSeconds, durationSeconds, completed } = req.body as any;
  if (!sessionId) return res.status(400).json({ error: "Sessão ausente" });
  if (videoId) {
    const existing = (await db.select().from(progress).where(and(eq(progress.courseId, id), eq(progress.sessionId, sessionId), eq(progress.videoId, videoId))))[0];
    const payload = {
      sessionId,
      courseId: id,
      videoId,
      watchedSeconds: Number(watchedSeconds ?? 0),
      durationSeconds: Number(durationSeconds ?? 0),
      completed: completed ? 1 : 0,
      updatedAt: Math.floor(Date.now() / 1000),
    } as any;
    if (existing) {
      await db.update(progress).set(payload).where(eq(progress.id, existing.id as number));
    } else {
      await db.insert(progress).values(payload);
    }
  }
  const vids = await db.select().from(courseVideos).where(eq(courseVideos.courseId, id));
  const prog = await db.select().from(progress).where(and(eq(progress.courseId, id), eq(progress.sessionId, sessionId)));
  const completedCount = prog.filter(p => p.completed as unknown as number === 1).length;
  res.json({ ok: true, total: vids.length, completed: completedCount });
});

// Creator Auth
app.get("/creator/login", (req, res) => res.render("creator_login"));
app.get("/creator/register", (req, res) => res.render("creator_register"));

app.post("/creator/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    const inserted = await db.insert(creators).values({ name, email, passwordHash: hash }).returning({ id: creators.id });
    const token = signToken({ id: inserted[0].id as number, role: "creator", name, email });
    res.cookie("creator_token", token, { httpOnly: true });
    res.redirect("/creator/dashboard");
  } catch (e) {
    res.status(400).send("Erro ao registrar: " + (e as Error).message);
  }
});

app.post("/creator/login", async (req, res) => {
  const { email, password } = req.body;
  const user = (await db.select().from(creators).where(eq(creators.email, email)))[0];
  if (!user) return res.status(401).send("Credenciais inválidas");
  const ok = await bcrypt.compare(password, user.passwordHash as string);
  if (!ok) return res.status(401).send("Credenciais inválidas");
  const token = signToken({ id: user.id as number, role: "creator", name: user.name as string, email });
  res.cookie("creator_token", token, { httpOnly: true });
  res.redirect("/creator/dashboard");
});

// Student Auth
app.get("/student/login", (req, res) => res.render("student_login"));
app.get("/student/register", (req, res) => res.render("student_register"));

app.post("/student/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    const inserted = await db.insert(students).values({ name, email, passwordHash: hash }).returning({ id: students.id });
    const token = signToken({ id: inserted[0].id as number, role: "student", name, email });
    res.cookie("student_token", token, { httpOnly: true });
    res.redirect("/student/dashboard");
  } catch (e) {
    res.status(400).send("Erro ao registrar: " + (e as Error).message);
  }
});

app.post("/student/login", async (req, res) => {
  const { email, password } = req.body;
  const user = (await db.select().from(students).where(eq(students.email, email)))[0];
  if (!user) return res.status(401).send("Credenciais inválidas");
  const ok = await bcrypt.compare(password, user.passwordHash as string);
  if (!ok) return res.status(401).send("Credenciais inválidas");
  const token = signToken({ id: user.id as number, role: "student", name: user.name as string, email });
  res.cookie("student_token", token, { httpOnly: true });
  res.redirect("/student/dashboard");
});

// Student Dashboard & logout
import { requireStudent } from "./auth";
app.get("/student/dashboard", requireStudent, async (req, res) => {
  const user = (req as any).user;
  // cursos comprados (pagos)
  const myTransactions = await db.select().from(transactions).where(and(eq(transactions.studentId, user.id), eq(transactions.status, "paid")));
  const allCourses = await db.select().from(courses);
  const myCourses = myTransactions.map(t => allCourses.find(c => (c.id as number) === (t.courseId as number))).filter(Boolean);
  // certificados
  const myCertificatesRaw = await db.select().from(certificates).where(eq(certificates.studentId, user.id));
  const myCertificates = myCertificatesRaw.map(c => ({
    ...c,
    fileUrl: "/certificados/" + path.basename(c.pdfPath as string)
  }));
  res.render("student_dashboard", { user, courses: myCourses, certificates: myCertificates });
});

app.post("/student/logout", (req, res) => {
  res.clearCookie("student_token");
  res.redirect("/");
});

// Creator Dashboard & CRUD
app.get("/creator/dashboard", requireCreator, async (req, res) => {
  const user = (req as any).user;
  const myCourses = await db.select().from(courses).where(eq(courses.creatorId, user.id));
  const myTransactions = await db.select().from(transactions).where(eq(transactions.creatorId, user.id));
  const gross = myTransactions.reduce((s, t) => s + (t.grossCents as number), 0);
  const net = myTransactions.reduce((s, t) => s + (t.netCents as number), 0);
  res.render("creator_dashboard", { user, courses: myCourses, gross, net, transactions: myTransactions });
});

app.post("/creator/course", requireCreator, async (req, res) => {
  const user = (req as any).user;
  const { title, description, playlistUrl, priceCents, workloadMinutes, slug, minScorePercent, attemptsAllowed } = req.body;
  try {
    // Basic validations
    const t = String(title || '').trim();
    const s = String(slug || '').trim();
    const price = Number(priceCents);
    const minScore = Number(minScorePercent ?? 70);
    const attempts = attemptsAllowed ? Number(attemptsAllowed) : null;
    if (!t || t.length < 3) throw new Error('Título muito curto');
    if (!s || !/^[a-z0-9-]+$/.test(s)) throw new Error('Slug deve conter apenas letras minúsculas, números e hífen');
    if (!Number.isFinite(price) || price <= 0) throw new Error('Preço inválido');
    if (!Number.isFinite(minScore) || minScore < 0 || minScore > 100) throw new Error('Nota mínima deve estar entre 0 e 100');
    if (attempts != null && (!Number.isInteger(attempts) || attempts < 0)) throw new Error('Tentativas permitidas inválidas');
    const inserted = await db.insert(courses).values({
      creatorId: user.id,
      title: t,
      description: (description?.trim() || "Descrição não informada"),
      playlistUrl,
      priceCents: price,
      workloadMinutes: workloadMinutes ? Number(workloadMinutes) : null,
      slug: s,
      minScorePercent: minScore,
      attemptsAllowed: attempts,
    }).returning({ id: courses.id });
    const courseId = inserted[0].id as number;
    res.redirect(`/creator/course/${courseId}/questions`);
  } catch (e) {
    res.status(400).send("Erro ao criar curso: " + (e as Error).message);
  }
});

app.post("/creator/questions", requireCreator, async (req, res) => {
  const { courseId, items } = req.body; // items: [{ text, options: [{text, correct}] }]
  try {
    const list = Array.isArray(items) ? items : [];
    if (list.length === 0) throw new Error('Inclua ao menos uma pergunta');
    for (const [idx, q] of list.entries()) {
      const qText = String(q.text || '').trim();
      if (qText.length < 3) throw new Error('Pergunta muito curta');
      const optsList = Array.isArray(q.options) ? q.options : [];
      if (optsList.length < 2) throw new Error('Cada pergunta precisa de ao menos 2 opções');
      const hasCorrect = optsList.some(o => !!o.correct);
      if (!hasCorrect) throw new Error('Marque ao menos uma opção correta por pergunta');
      const qIns = await db.insert(questions).values({ courseId: Number(courseId), text: qText, order: idx + 1 }).returning({ id: questions.id });
      const qId = qIns[0].id as number;
      for (const opt of optsList) {
        await db.insert(options).values({ questionId: qId, text: String(opt.text || '').trim(), correct: !!opt.correct });
      }
    }
    res.redirect(`/creator/course/${courseId}/certificate-template`);
  } catch (e) {
    res.status(400).send("Erro ao criar perguntas: " + (e as Error).message);
  }
});

// Exam flow
app.get("/exam/:courseId", async (req, res) => {
  const courseId = Number(req.params.courseId);
  const course = (await db.select().from(courses).where(eq(courses.id, courseId)))[0];
  if (!course) return res.status(404).send("Curso não encontrado");
  // Enforce completion of playlist before exam (if playlist exists)
  const vids = await db.select().from(courseVideos).where(eq(courseVideos.courseId, courseId));
  if (vids.length > 0) {
    const sessionId = (req as any).cookies?.cp_session;
    const prog = sessionId ? await db.select().from(progress).where(and(eq(progress.courseId, courseId), eq(progress.sessionId, sessionId))) : [];
    const completedCount = prog.filter(p => p.completed as unknown as number === 1).length;
    if (completedCount < vids.length) {
      return res.status(400).send("Conclua todas as aulas da playlist antes de iniciar a prova.");
    }
  }
  const qs = await db.select().from(questions).where(eq(questions.courseId, courseId));
  const opts = await db.select().from(options);
  const full = qs.map(q => ({
    id: q.id,
    text: q.text,
    options: opts.filter(o => o.questionId === q.id).map(o => ({ id: o.id, text: o.text }))
  }));
  // Shuffle for MVP
  full.sort(() => Math.random() - 0.5);
  res.render("exam", { course, questions: full });
});

app.post("/exam/:courseId", async (req, res) => {
  const courseId = Number(req.params.courseId);
  const course = (await db.select().from(courses).where(eq(courses.id, courseId)))[0];
  if (!course) return res.status(404).send("Curso não encontrado");
  // cria/usa aluno a partir do nome/email enviados
  const { student_name, student_email } = req.body;
  if (!student_name || !student_email) return res.status(400).send("Informe nome e e-mail");
  let student = (await db.select().from(students).where(eq(students.email, student_email)))[0];
  if (!student) {
    const hash = await bcrypt.hash(`${Date.now()}-${student_email}`, 10);
    const ins = await db.insert(students).values({ name: student_name, email: student_email, passwordHash: hash }).returning({ id: students.id });
    student = { id: ins[0].id } as any;
  }
  const body = req.body || {};
  const qs = await db.select().from(questions).where(eq(questions.courseId, courseId));
  const optsAll = await db.select().from(options);
  let correctCount = 0;
  for (const q of qs) {
    const selected = Number(body[`q_${q.id}`]);
    const correctOpt = optsAll.find(o => o.questionId === q.id && (o.correct as unknown as number) === 1);
    const isCorrect = selected && correctOpt && selected === (correctOpt.id as number);
    if (isCorrect) correctCount++;
  }
  const scorePercent = Math.round((correctCount / Math.max(qs.length, 1)) * 100);
  const approved = scorePercent >= (course.minScorePercent as number);
  const examIns = await db.insert(exams).values({ studentId: student.id as number, courseId, scorePercent, approved, ip: req.ip }).returning({ id: exams.id });
  const examId = examIns[0].id as number;
  // Save answers
  for (const q of qs) {
    const selected = Number(body[`q_${q.id}`]);
    const correctOpt = optsAll.find(o => o.questionId === q.id && (o.correct as unknown as number) === 1);
    const isCorrect = selected && correctOpt && selected === (correctOpt.id as number);
    await db.insert(answers).values({ examId, questionId: q.id as number, optionId: selected || 0, correct: !!isCorrect });
  }
  if (!approved) {
    return res.render("exam_result", { course, scorePercent, approved });
  }
  // Proceed to payment
  res.render("payment", { course, scorePercent, examId });
});

// Payment
app.post("/payment/create", async (req, res) => {
  const { examId } = req.body;
  const exam = (await db.select().from(exams).where(eq(exams.id, Number(examId))))[0];
  if (!exam) return res.status(400).send("Exame inválido");
  const course = (await db.select().from(courses).where(eq(courses.id, Number(exam.courseId))))[0];
  if (!course || !stripe) return res.status(400).send("Pagamento indisponível");

  const commissionPercent = (await db.select().from(creators).where(eq(creators.id, course.creatorId)))[0]?.commissionPercent ?? 20;
  const gross = course.priceCents as number;
  const fee = Math.round((gross * 20) / 100); // plataforma 20%
  const net = gross - fee;

  const trxIns = await db.insert(transactions).values({
    courseId: course.id as number,
    creatorId: course.creatorId as number,
    studentId: exam.studentId as number,
    grossCents: gross,
    platformFeeCents: fee,
    netCents: net,
    provider: "stripe",
    status: "pending",
  }).returning({ id: transactions.id });
  const transactionId = trxIns[0].id as number;

  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    payment_method_types: ["card"],
    line_items: [{
      price_data: {
        currency: "brl",
        product_data: { name: `Certificado: ${course.title}` },
        unit_amount: gross,
      },
      quantity: 1,
    }],
    success_url: `${process.env.PUBLIC_URL || "http://localhost:3000"}/payment/success?transactionId=${transactionId}`,
    cancel_url: `${process.env.PUBLIC_URL || "http://localhost:3000"}/payment/cancel`,
    metadata: { transactionId: String(transactionId), courseId: String(course.id), studentId: String(exam.studentId), scorePercent: String(exam.scorePercent) },
  });

  await db.update(transactions).set({ providerPaymentId: session.id }).where(eq(transactions.id, transactionId));

  res.json({ url: session.url });
});

// Webhook Stripe
app.post("/payment/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    if (!stripe) return res.status(400).send("Stripe não configurado");
    const sig = req.headers["stripe-signature"] as string;
    const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET || "");

    if (event.type === "checkout.session.completed") {
      const session = event.data.object as Stripe.Checkout.Session;
      const transactionId = Number(session.metadata?.transactionId);
      const trx = (await db.select().from(transactions).where(eq(transactions.id, transactionId)))[0];
      if (!trx) return res.json({ ok: true });
      // mark paid
      await db.update(transactions).set({ status: "paid" }).where(eq(transactions.id, transactionId));
      // generate certificate
      await generateCertificate(trx, Number(session.metadata?.scorePercent));
    }

    res.json({ received: true });
  } catch (e) {
    console.error(e);
    res.status(400).send(`Webhook error: ${(e as Error).message}`);
  }
});

async function generateCertificate(trx: any, scorePercent: number) {
  const student = (await db.select().from(students).where(eq(students.id, trx.studentId)))[0];
  const course = (await db.select().from(courses).where(eq(courses.id, trx.courseId)))[0];
  const creator = (await db.select().from(creators).where(eq(creators.id, trx.creatorId)))[0];
  const code = Math.random().toString(36).slice(2, 10);
  const pdfPath = path.join(process.cwd(), "certificados", `${code}.pdf`);

  const doc = new PDFDocument({ size: "A4", margin: 50 });
  const stream = fs.createWriteStream(pdfPath);
  doc.pipe(stream);
  const templateId = (course.certificateTemplateId as number) || 1;
  let styles: any = getTemplateStyles(templateId);
  // Apply overrides from course configuration (JSON)
  let cfg: any = {};
  try {
    cfg = course.certificateTemplateConfig ? JSON.parse(course.certificateTemplateConfig as string) : {};
  } catch {}
  styles = {
    ...styles,
    ...(cfg.headerColor ? { headerColor: cfg.headerColor } : {}),
    ...(cfg.headerTextColor ? { headerTextColor: cfg.headerTextColor } : {}),
    ...(cfg.title ? { title: cfg.title } : {}),
    ...(cfg.centered != null ? { centered: !!cfg.centered } : {}),
    ...(cfg.qrPosition === 'right' ? { qrRight: true } : cfg.qrPosition === 'left' ? { qrRight: false } : {}),
    ...(cfg.align ? { align: cfg.align } : {}),
    ...(cfg.font ? { font: cfg.font } : {}),
  };
  // Background/header
  if (styles.headerColor) {
    doc.rect(0, 0, doc.page.width, 80).fill(styles.headerColor);
    doc.fillColor(styles.headerTextColor || '#000');
    if (styles.font) {
      try { doc.font(styles.font); } catch {}
    }
    doc.fontSize(24).text(styles.title || 'Certificado de Conclusão', 50, 30, { align: styles.align || 'left' });
    doc.fillColor('#000');
  } else {
    if (styles.font) {
      try { doc.font(styles.font); } catch {}
    }
    doc.fontSize(24).text(styles.title || 'Certificado de Conclusão', { align: styles.align || (styles.centered ? 'center' : 'left') });
  }

  doc.moveDown();
  doc.fontSize(14);
  const defaultBody = `Certificamos que ${student.name} concluiu o curso ${course.title} com nota ${scorePercent}% em ${new Date().toLocaleDateString()}. Código: ${code}.`;
  const bodyTemplate = cfg?.bodyText || defaultBody;
  const body = String(bodyTemplate)
    .replaceAll('{studentName}', String(student.name))
    .replaceAll('{courseTitle}', String(course.title))
    .replaceAll('{scorePercent}', String(scorePercent))
    .replaceAll('{date}', new Date().toLocaleDateString())
    .replaceAll('{creatorName}', String(creator.name))
    .replaceAll('{code}', code);
  doc.text(body, { align: styles.align || (styles.centered ? 'center' : 'left') });
  doc.moveDown();

  const validateUrl = `${process.env.PUBLIC_URL || "http://localhost:3000"}/certificate/${code}`;
  const qrData = await QRCode.toDataURL(validateUrl);
  const qrBase64 = qrData.split(",")[1];
  const qrBuf = Buffer.from(qrBase64, "base64");
  if (styles.qrRight) {
    doc.image(qrBuf, doc.page.width - 170, doc.page.height - 220, { fit: [120, 120] });
  } else {
    doc.image(qrBuf, { fit: [120, 120], align: "left" });
  }

  // Optional signature
  if (cfg?.signatureName) {
    doc.moveDown();
    doc.text(cfg.signatureName, { align: styles.align || (styles.centered ? 'center' : 'left') });
  }
  // Optional logo (local path under /public)
  if (cfg?.logoPath) {
    const p = path.join(process.cwd(), cfg.logoPath.replace(/^\//, ''));
    try {
      doc.image(p, 50, 90, { fit: [80, 80] });
    } catch {}
  }

  doc.end();

  await db.insert(certificates).values({ transactionId: trx.id, code, pdfPath, studentId: trx.studentId, courseId: trx.courseId, scorePercent });
}

function getTemplateStyles(id: number) {
  const presets: any = {
    1: { title: 'Certificado de Conclusão', centered: false },
    2: { title: 'Certificado', centered: true },
    3: { headerColor: '#111827', headerTextColor: '#fff', title: 'Certificado', centered: false, qrRight: true },
    4: { headerColor: '#2563eb', headerTextColor: '#fff', title: 'Certificado Oficial', centered: true },
    5: { headerColor: '#10b981', headerTextColor: '#fff', title: 'Certificado', qrRight: true },
    6: { headerColor: '#ef4444', headerTextColor: '#fff', title: 'Certificado', centered: true },
    7: { headerColor: '#f59e0b', headerTextColor: '#000', title: 'Certificado' },
    8: { headerColor: '#7c3aed', headerTextColor: '#fff', title: 'Certificado' },
    9: { headerColor: '#0ea5e9', headerTextColor: '#fff', title: 'Certificado' },
    10: { centered: true, qrRight: true },
    11: { headerColor: '#6b7280', headerTextColor: '#fff', title: 'Certificado' },
    12: { headerColor: '#374151', headerTextColor: '#fff', title: 'Certificado', centered: true },
    13: { headerColor: '#1f2937', headerTextColor: '#fff', title: 'Certificado' },
    14: { headerColor: '#059669', headerTextColor: '#fff', title: 'Certificado' },
    15: { headerColor: '#d97706', headerTextColor: '#fff', title: 'Certificado' },
    16: { headerColor: '#14b8a6', headerTextColor: '#fff', title: 'Certificado' },
    17: { headerColor: '#9333ea', headerTextColor: '#fff', title: 'Certificado' },
    18: { headerColor: '#dc2626', headerTextColor: '#fff', title: 'Certificado' },
    19: { headerColor: '#e11d48', headerTextColor: '#fff', title: 'Certificado' },
    20: { headerColor: '#3b82f6', headerTextColor: '#fff', title: 'Certificado', qrRight: true },
  };
  return presets[id] || presets[1];
}

// Certificate validation
app.get("/certificate/:code", async (req, res) => {
  const code = req.params.code;
  const cert = (await db.select().from(certificates).where(eq(certificates.code, code)))[0];
  if (!cert) return res.render("certificate_validated", { valid: false });
  const course = (await db.select().from(courses).where(eq(courses.id, cert.courseId)))[0];
  const student = (await db.select().from(students).where(eq(students.id, cert.studentId)))[0];
  res.render("certificate_validated", { valid: true, cert, course, student });
});

// Fluxo simplificado: sem dashboard de aluno

// Minimal pages for success/cancel
app.get("/payment/success", (req, res) => {
  res.render("payment_success");
});
app.get("/payment/cancel", (req, res) => {
  res.render("payment_cancel");
});

// Creator utility link to course page
app.get("/c/:slug", async (req, res) => {
  const slug = req.params.slug;
  const course = (await db.select().from(courses).where(eq(courses.slug, slug)))[0];
  if (!course) return res.status(404).send("Curso não encontrado");
  res.redirect(`/course/${course.id}`);
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`CertiPay rodando em http://localhost:${port}`);
});
// Questions builder
app.get("/creator/course/:id/questions", requireCreator, async (req, res) => {
  const id = Number(req.params.id);
  const course = (await db.select().from(courses).where(eq(courses.id, id)))[0];
  if (!course) return res.status(404).send("Curso não encontrado");
  res.render("creator_questions", { course });
});
// Certificate template selection
app.get("/creator/course/:id/certificate-template", requireCreator, async (req, res) => {
  const id = Number(req.params.id);
  const course = (await db.select().from(courses).where(eq(courses.id, id)))[0];
  if (!course) return res.status(404).send("Curso não encontrado");
  const templates = Array.from({ length: 20 }).map((_, i) => ({ id: i + 1, name: `Modelo ${i + 1}` }));
  res.render("creator_certificate_templates", { course, templates });
});

app.post("/creator/course/:id/certificate-template", requireCreator, async (req, res) => {
  const id = Number(req.params.id);
  const { templateId } = req.body;
  await db.update(courses).set({ certificateTemplateId: Number(templateId) }).where(eq(courses.id, id));
  res.redirect(`/course/${id}`);
});

// Certificate editor (configurable templates)
app.get("/creator/course/:id/certificate-editor", requireCreator, async (req, res) => {
  const id = Number(req.params.id);
  const course = (await db.select().from(courses).where(eq(courses.id, id)))[0];
  if (!course) return res.status(404).send("Curso não encontrado");
  let cfg: any = {};
  try { cfg = course.certificateTemplateConfig ? JSON.parse(course.certificateTemplateConfig as string) : {}; } catch {}
  res.render("creator_certificate_editor", { course, config: cfg });
});

app.post("/creator/course/:id/certificate-editor", requireCreator, async (req, res) => {
  const id = Number(req.params.id);
  const payload = {
    title: req.body.title,
    bodyText: req.body.bodyText,
    headerColor: req.body.headerColor,
    headerTextColor: req.body.headerTextColor,
    centered: req.body.centered === 'on',
    align: req.body.align,
    font: req.body.font,
    qrPosition: req.body.qrPosition,
    signatureName: req.body.signatureName,
    logoPath: req.body.logoPath,
  };
  await db.update(courses)
    .set({ certificateTemplateConfig: JSON.stringify(payload) })
    .where(eq(courses.id, id));
  res.redirect(`/creator/course/${id}/certificate-editor`);
});