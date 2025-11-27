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
  enrollments,
} from "./schema";
import { eq, and, or, like, inArray } from "drizzle-orm";
import { requireCreator, signToken } from "./auth";
import PDFDocument from "pdfkit";
import QRCode from "qrcode";
import fs from "fs";
import Stripe from "stripe";
import { MercadoPagoConfig, Preference, Payment } from "mercadopago";

const stripeSecret = process.env.STRIPE_SECRET || "";
const stripe = stripeSecret ? new Stripe(stripeSecret) : null;

// Mercado Pago
const mpAccessToken = process.env.MP_ACCESS_TOKEN || "";
const mpClient = mpAccessToken ? new MercadoPagoConfig({ accessToken: mpAccessToken }) : null;
const mpPref = mpClient ? new Preference(mpClient) : null;
const mpPay = mpClient ? new Payment(mpClient) : null;

const app = express();
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Simple in-memory rate limiting (basic protection)
type RateEntry = { count: number; resetAt: number };
const rateStore = new Map<string, RateEntry>();
function rateLimit({ windowMs, max }: { windowMs: number; max: number }) {
  return (req: any, res: any, next: any) => {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    const entry = rateStore.get(key);
    if (!entry || entry.resetAt < now) {
      rateStore.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (entry.count >= max) {
      const retry = Math.max(0, Math.floor((entry.resetAt - now) / 1000));
      res.set('Retry-After', String(retry));
      return res.status(429).json({ error: 'Muitas requisições, tente novamente mais tarde.' });
    }
    entry.count += 1;
    rateStore.set(key, entry);
    next();
  };
}
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
app.use("/certificados", express.static(path.join(process.cwd(), "certificados"), {
  etag: false,
  lastModified: false,
  maxAge: 0,
  setHeaders: (res) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }
}));

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
  const student = (res as any).locals.student;
  let enrolledCourseIds: number[] = [];
  if (student) {
    const myEnrolls = await db.select().from(enrollments).where(eq(enrollments.studentId, student.id));
    enrolledCourseIds = myEnrolls.map(e => e.courseId as number);
  }
  res.render("index", { courses: allCourses, q, enrolledCourseIds });
});

// Iniciar curso a partir de uma URL de playlist (ou vídeo único)
app.post("/start", rateLimit({ windowMs: 60_000, max: 10 }), async (req, res) => {
  try {
    const url = String((req.body.url || req.body.playlistUrl || req.body.q || '').trim());
    if (!url) return res.status(400).send("Informe o link da playlist ou vídeo");

    function getParam(u: string, name: string) {
      try { const uu = new URL(u); return uu.searchParams.get(name); } catch { return null; }
    }
    function extractVideoIdFromUrl(u: string): string | null {
      try {
        const uu = new URL(u);
        const host = uu.hostname.replace(/^m\./, '');
        const vParam = uu.searchParams.get('v');
        const idPattern = /^[a-zA-Z0-9_-]{11}$/;
        if (vParam && idPattern.test(vParam)) return vParam;
        // youtu.be/<id>
        if (host === 'youtu.be') {
          const seg = uu.pathname.split('/').filter(Boolean)[0];
          if (seg && idPattern.test(seg)) return seg;
        }
        // /shorts/<id> or /embed/<id>
        const parts = uu.pathname.split('/').filter(Boolean);
        if (parts.length >= 2 && (parts[0] === 'shorts' || parts[0] === 'embed')) {
          const seg = parts[1];
          if (seg && idPattern.test(seg)) return seg;
        }
        return null;
      } catch { return null; }
    }

    const playlistId = getParam(url, 'list');
    const singleVideoId = extractVideoIdFromUrl(url);

    let videoIds: string[] = [];
    let courseTitle = 'Curso pessoal';
    let channelName: string | null = null;
    let playlistHtml: string | null = null;

    // Título via oEmbed como melhor esforço
    try {
      const oe = await fetch(`https://www.youtube.com/oembed?format=json&url=${encodeURIComponent(url)}`);
      if (oe.ok) { const data = await oe.json();
        courseTitle = String(data.title || courseTitle);
        channelName = String((data.author_name || '').trim()) || channelName;
      }
    } catch {}

    const idPattern = /^[a-zA-Z0-9_-]{11}$/;
    if (playlistId) {
      try {
        const resp = await fetch(`https://www.youtube.com/playlist?hl=pt-BR&list=${encodeURIComponent(playlistId)}`, {
          headers: { 'user-agent': 'Mozilla/5.0', 'accept-language': 'pt-BR,pt;q=0.9,en;q=0.8' }
        } as any);
        if (resp.ok) {
          const html = await resp.text();
          playlistHtml = html;
          // Primeiro, tentar parsear ytInitialData
          const dataMatch = html.match(/ytInitialData\s*=\s*(\{.*?\});/s);
          if (dataMatch) {
            try {
              const json = JSON.parse(dataMatch[1]);
              // Tentar extrair título da playlist e nome do canal
              const pTitle = json?.metadata?.playlistMetadataRenderer?.title ||
                json?.header?.playlistHeaderRenderer?.titleText?.simpleText ||
                json?.microformat?.microformatDataRenderer?.title || null;
              if (pTitle && typeof pTitle === 'string') {
                courseTitle = String(pTitle).trim();
              }
              const ownerRun = json?.header?.playlistHeaderRenderer?.ownerText?.runs?.[0]?.text || null;
              if (ownerRun && typeof ownerRun === 'string') {
                channelName = String(ownerRun).trim();
              }
              const tabs = json.contents?.twoColumnBrowseResultsRenderer?.tabs || [];
              const tab = tabs.find((t: any) => t?.tabRenderer?.selected) || tabs[0];
              const contents = tab?.tabRenderer?.content?.sectionListRenderer?.contents || [];
              const section = contents.find((c: any) => c?.itemSectionRenderer)?.itemSectionRenderer || contents[0]?.itemSectionRenderer;
              const list = section?.contents?.find((x: any) => x?.playlistVideoListRenderer)?.playlistVideoListRenderer?.contents || [];
              const idsA = [] as string[];
              for (const item of list) {
                const r = (item.playlistVideoRenderer || item.playlistPanelVideoRenderer);
                const vid = r?.videoId;
                if (vid && idPattern.test(vid)) idsA.push(vid);
              }
              videoIds = Array.from(new Set(idsA));
            } catch {}
          }
          // Fallback: regex direta
          if (videoIds.length === 0) {
            const matches = html.match(/\"videoId\":\"([a-zA-Z0-9_-]{11})\"/g) || [];
            const ids = matches.map(m => m.split('\":\"')[1]).filter(x => idPattern.test(x));
            videoIds = Array.from(new Set(ids)).slice(0, 200);
          }
          // Fallback: título da página
          if (playlistId && (!courseTitle || courseTitle === 'Curso pessoal')) {
            const og = html.match(/<meta\s+property="og:title"\s+content="([^"]+)"/i)?.[1];
            const t = og || html.match(/<title>([^<]+)<\/title>/i)?.[1] || '';
            if (t) courseTitle = t.replace(/\s*-\s*YouTube$/i, '').trim();
          }
        }
      } catch {}
    }

    if (!playlistId && singleVideoId && idPattern.test(singleVideoId)) {
      videoIds = [singleVideoId];
      // Obter canal pelo oEmbed do vídeo especificamente
      try {
        const oe2 = await fetch(`https://www.youtube.com/oembed?format=json&url=${encodeURIComponent(`https://www.youtube.com/watch?v=${singleVideoId}`)}`);
        if (oe2.ok) { const data2 = await oe2.json(); channelName = String((data2.author_name || '').trim()) || channelName; }
      } catch {}
    }

    if (videoIds.length === 0) {
      return res.status(400).send("Não foi possível extrair os vídeos da playlist — verifique o link. Dica: use o link da página da playlist (youtube.com/playlist?list=...) ou cole o link do vídeo.");
    }

    // Heurística/A.I. para determinar o nome canônico do curso (não o título do vídeo)
    async function inferCanonicalCourseTitle(): Promise<string> {
      // Se temos playlist, o título da playlist é o melhor candidato
      if (playlistId && courseTitle && courseTitle !== 'Curso pessoal') return String(courseTitle);
      // Tentar enriquecer com títulos das primeiras aulas
      const f = (global as any).fetch ? (global as any).fetch : (await import("node-fetch")).default as any;
      const titles: string[] = [];
      for (const vid of videoIds.slice(0, 8)) {
        try {
          const respV = await f(`https://www.youtube.com/watch?v=${vid}`, { headers: { "User-Agent": "Mozilla/5.0", "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8" } });
          const htmlV = await respV.text();
          const og = htmlV.match(/<meta\s+property="og:title"\s+content="([^"]+)"/i)?.[1];
          const vd = htmlV.match(/"videoDetails"\s*:\s*\{[^}]*"title"\s*:\s*"([^"]+)"/i)?.[1];
          const t = (og || vd || htmlV.match(/<title>([^<]+)<\/title>/i)?.[1] || '').replace(/\s*-\s*YouTube$/i, '').trim();
          if (t) titles.push(t);
          // canal por fallback
          if (!channelName) {
            const author = htmlV.match(/<link\s+itemprop="name"\s+content="([^"]+)"/i)?.[1] || htmlV.match(/"ownerChannelName"\s*:\s*"([^"]+)"/i)?.[1];
            if (author) channelName = String(author).trim();
          }
        } catch {}
      }
      // Heurística: remover padrões de aula/episódio e extrair prefixo comum
      function normalize(s: string) {
        return s
          .replace(/\b(aula|lesson|episódio|episodio|parte|módulo|modulo|capítulo|capitulo)\s*\d+\b/gi, '')
          .replace(/\b(parte|part)\s*\d+\b/gi, '')
          .replace(/[#-]\s*\d+\b/g, '')
          .replace(/\([^)]*\)|\[[^]]*\]/g, '')
          .replace(/\s+/g, ' ')
          .trim();
      }
      const norm = titles.map(normalize).filter(Boolean);
      if (norm.length) {
        // prefixo comum
        const first = norm[0];
        let common = first;
        for (const t of norm.slice(1)) {
          let i = 0; while (i < common.length && i < t.length && common[i].toLowerCase() === t[i].toLowerCase()) i++;
          common = common.slice(0, i).trim();
          if (common.length < 8) break; // evitar prefixos curtos demais
        }
        const candidate = (common.length >= 8 ? common : first);
        if (candidate) return candidate;
      }
      // A.I. como última etapa
      try {
        const apiKey = process.env.OPENAI_API_KEY || process.env.AI_API_KEY || "";
        if (apiKey) {
          const prompt = [
            "Extraia APENAS o nome canônico do curso/playlist a partir dos títulos abaixo.",
            "Ignore números de aula, parte, episódio e detalhes específicos do vídeo.",
            "Responda apenas em JSON simples: {\"courseName\": \"...\"}.",
            `Títulos: ${titles.join(' | ')}`,
            playlistHtml ? `Página da playlist presente.` : `Sem playlist.`
          ].join("\n");
          const resp = await f("https://api.openai.com/v1/chat/completions", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}` },
            body: JSON.stringify({ model: process.env.OPENAI_MODEL || "gpt-4o-mini", messages: [{ role: "user", content: prompt }], temperature: 0 }),
          });
          const data = await resp.json();
          let content = data?.choices?.[0]?.message?.content || "";
          content = content.replace(/```json|```/g, "").trim();
          const parsed = JSON.parse(content);
          if (parsed?.courseName) return String(parsed.courseName).trim();
        }
      } catch {}
      return courseTitle || 'Curso pessoal';
    }

    const canonicalCourseTitle = await inferCanonicalCourseTitle();

    let systemCreator = (await db.select().from(creators).where(eq(creators.email, 'system@certipay')))[0];
    if (!systemCreator) {
      const ins = await db.insert(creators).values({ name: 'Sistema', email: 'system@certipay', passwordHash: 'x', commissionPercent: 20 }).returning({ id: creators.id });
      systemCreator = { id: ins[0].id } as any;
    }

    const slug = `personal-${Math.random().toString(36).slice(2, 10)}`;
    const courseIns = await db.insert(courses).values({
      creatorId: systemCreator.id as number,
      title: canonicalCourseTitle,
      description: `Curso importado do canal ${channelName || 'desconhecido'}`,
      playlistUrl: url,
      priceCents: 0,
      workloadMinutes: videoIds.length * 10,
      slug,
      minScorePercent: 0,
      attemptsAllowed: null,
    }).returning({ id: courses.id });
    const courseId = courseIns[0].id as number;

    // Persistir canal e título canônico no config do certificado (imutáveis por não haver UI de edição)
    try {
      const baseCfg = {
        channelName: channelName || undefined,
        canonicalCourseTitle,
        immutable: true,
      };
      await db.update(courses).set({ certificateTemplateConfig: JSON.stringify(baseCfg) }).where(eq(courses.id, courseId));
    } catch {}

    let pos = 1;
    for (const vid of videoIds) { await db.insert(courseVideos).values({ courseId, videoId: vid, position: pos++ }); }

    const student = (res as any).locals.student;
    if (student) { await db.insert(enrollments).values({ studentId: student.id as number, courseId }); }

    res.redirect(`/course/${courseId}`);
  } catch (e) {
    res.status(400).send(`Erro ao iniciar curso: ${(e as Error).message}`);
  }
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

// Compra direta de certificado (sem exame)
app.get("/course/:id/certificate", async (req, res) => {
  const id = Number(req.params.id);
  const course = (await db.select().from(courses).where(eq(courses.id, id)))[0];
  if (!course) return res.status(404).send("Curso não encontrado");
  if ((course.priceCents as number) > 0 && !stripe) {
    return res.status(400).send("Pagamento indisponível: Stripe não configurado");
  }
  res.render("payment", { course });
});

// Fallback: acessar /payment sem contexto de curso
// Permite testar a emissão de certificado escolhendo o primeiro curso disponível,
// ou redireciona para a Home quando não há cursos.
app.get("/payment", async (req, res) => {
  const courseId = Number((req.query.courseId as string) || 0);
  if (Number.isFinite(courseId) && courseId > 0) {
    const course = (await db.select().from(courses).where(eq(courses.id, courseId)))[0];
    if (course) return res.render("payment", { course });
  }
  const all = await db.select().from(courses);
  const first = all[0];
  if (!first) return res.redirect("/");
  return res.redirect(`/course/${first.id}/certificate`);
});

// Matrícula gratuita em curso
// Matrícula desativada
app.post("/course/:id/enroll", async (req, res) => res.status(404).send("Indisponível"));

// Save playlist items (from client) — restricted to course creator
app.post("/course/:id/playlist", requireCreator, async (req, res) => {
  const id = Number(req.params.id);
  const user = (req as any).user;
  const { videoIds } = req.body as { videoIds: string[] };

  // Validate params
  if (!Array.isArray(videoIds) || videoIds.length === 0) {
    return res.status(400).json({ error: "Lista vazia" });
  }
  if (videoIds.length > 500) {
    return res.status(400).json({ error: "Lista muito grande" });
  }

  // Ownership check
  const course = (await db.select().from(courses).where(eq(courses.id, id)))[0];
  if (!course) return res.status(404).json({ error: "Curso não encontrado" });
  if ((course.creatorId as number) !== (user.id as number)) {
    return res.status(403).json({ error: "Proibido: apenas o criador pode editar a playlist" });
  }

  // Sanitize and de-duplicate video IDs (YouTube-like pattern)
  const idPattern = /^[a-zA-Z0-9_-]{11}$/;
  const seen = new Set<string>();
  const clean = videoIds.filter((v) => {
    const s = String(v || '').trim();
    if (!idPattern.test(s)) return false;
    if (seen.has(s)) return false;
    seen.add(s);
    return true;
  });
  if (clean.length === 0) {
    return res.status(400).json({ error: "IDs inválidos" });
  }

  // Replace existing with cleaned list
  await db.delete(courseVideos).where(eq(courseVideos.courseId, id));
  for (const [i, v] of clean.entries()) {
    await db.insert(courseVideos).values({ courseId: id, videoId: v, position: i });
  }
  res.json({ ok: true, count: clean.length });
});

// Progresso local — no-op no servidor
app.post("/course/:id/progress", async (req, res) => {
  const id = Number(req.params.id);
  const vids = await db.select().from(courseVideos).where(eq(courseVideos.courseId, id));
  res.json({ ok: true, total: vids.length, completed: 0 });
});

// API para SPA React
app.get("/api/courses", async (req, res) => {
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
  res.json(allCourses.map(c => ({
    id: c.id,
    title: c.title,
    description: c.description,
    slug: c.slug,
    priceCents: c.priceCents,
    workloadMinutes: c.workloadMinutes,
    minScorePercent: c.minScorePercent,
  })));
});

// Course metadata (public)
app.get("/api/course/:id", async (req, res) => {
  const id = Number(req.params.id);
  const course = (await db.select().from(courses).where(eq(courses.id, id)))[0];
  if (!course) return res.status(404).json({ error: "Curso não encontrado" });
  res.json({
    id: course.id,
    title: course.title,
    description: course.description,
    slug: course.slug,
    priceCents: course.priceCents,
    workloadMinutes: course.workloadMinutes,
    minScorePercent: course.minScorePercent,
    attemptsAllowed: course.attemptsAllowed,
  });
});

// Course playlist (public read)
app.get("/api/course/:id/playlist", async (req, res) => {
  const id = Number(req.params.id);
  const course = (await db.select().from(courses).where(eq(courses.id, id)))[0];
  if (!course) return res.status(404).json({ error: "Curso não encontrado" });
  const vids = await db.select().from(courseVideos).where(eq(courseVideos.courseId, id));
  const items = vids
    .sort((a, b) => (a.position as number) - (b.position as number))
    .map(v => ({ videoId: v.videoId, position: v.position }));
  res.json({ items });
});

app.get("/api/me", (req, res) => {
  const student = (res as any).locals.student;
  res.json(student ? { id: student.id, name: student.name, email: student.email } : null);
});

app.get("/api/me/enrollments", async (req, res) => {
  const student = (res as any).locals.student;
  if (!student) return res.status(200).json({ courseIds: [] });
  const rows = await db.select().from(enrollments).where(eq(enrollments.studentId, student.id));
  res.json({ courseIds: rows.map(r => r.courseId as number) });
});

app.post("/api/course/:id/enroll", async (req, res) => res.status(404).json({ error: "Indisponível" }));

// Creator desativado
app.get("/creator/login", (req, res) => res.status(404).send("Indisponível"));
app.get("/creator/register", (req, res) => res.status(404).send("Indisponível"));
app.post("/creator/register", async (req, res) => res.status(404).send("Indisponível"));
app.post("/creator/login", async (req, res) => res.status(404).send("Indisponível"));

// Área do aluno desativada
app.get("/student/login", (req, res) => res.status(404).send("Indisponível"));
app.get("/student/register", (req, res) => res.status(404).send("Indisponível"));
app.post("/student/register", async (req, res) => res.status(404).send("Indisponível"));
app.post("/student/login", async (req, res) => res.status(404).send("Indisponível"));

// Student Dashboard & logout
app.get("/student/dashboard", async (req, res) => res.status(404).send("Indisponível"));

app.post("/student/logout", (req, res) => res.status(404).send("Indisponível"));

// Creator Dashboard & CRUD
app.get("/creator/dashboard", requireCreator, async (req, res) => res.status(404).send("Indisponível"));

app.post("/creator/course", requireCreator, async (req, res) => res.status(404).send("Indisponível"));

app.post("/creator/questions", requireCreator, async (req, res) => res.status(404).send("Indisponível"));

// Exam flow
async function generateAiQuestionsForCourse(courseId: number) {
  const course = (await db.select().from(courses).where(eq(courses.id, courseId)))[0];
  if (!course) throw new Error("Curso não encontrado");
  // Limpar questões antigas do curso para evitar repetição e acúmulo
  const existingQs = await db.select().from(questions).where(eq(questions.courseId, courseId));
  if (existingQs.length) {
    const ids = existingQs.map(q => q.id as number);
    try {
      if (ids.length) {
        await db.delete(options).where(inArray(options.questionId, ids));
      }
      await db.delete(questions).where(eq(questions.courseId, courseId));
    } catch (e) {
      // Se falhar a remoção, seguimos para gerar novas sem interromper
    }
  }

  const vids = (await db.select().from(courseVideos).where(eq(courseVideos.courseId, courseId)))
    .sort((a,b)=> (a.position||0)-(b.position||0));

  // Tentar obter títulos das aulas para enriquecer o prompt
  async function fetchVideoTitle(videoId: string): Promise<string | null> {
    try {
      const f = (global as any).fetch ? (global as any).fetch : (await import("node-fetch")).default as any;
      const resp = await f(`https://www.youtube.com/watch?v=${videoId}`, {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/117.0 Safari/537.36",
          "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
        },
      });
      const html = await resp.text();
      const og = html.match(/<meta\s+property="og:title"\s+content="([^"]+)"/i)?.[1];
      if (og) return og;
      const vd = html.match(/"videoDetails"\s*:\s*\{[^}]*"title"\s*:\s*"([^"]+)"/i)?.[1];
      if (vd) return vd;
      const t = html.match(/<title>([^<]+)<\/title>/i)?.[1];
      return t ? t.replace(/\s*-\s*YouTube$/i, "").trim() : null;
    } catch {
      return null;
    }
  }

  const titles: string[] = [];
  for (const v of vids.slice(0, 10)) {
    const t = await fetchVideoTitle(v.videoId as string);
    titles.push(t || `Aula ${v.position || ""}`);
  }

  const apiKey = process.env.OPENAI_API_KEY || process.env.AI_API_KEY || "";
  let generated: Array<{ question: string; options: string[]; answerIndex: number }> | null = null;
  try {
    if (apiKey) {
      const f = (global as any).fetch ? (global as any).fetch : (await import("node-fetch")).default as any;
      const prompt = [
        `Você é um gerador de provas simples.`,
        `Crie 6 questões fáceis e diretas, de múltipla escolha (4 alternativas, apenas 1 correta).`,
        `Cada questão deve focar em UM tópico específico entre os títulos das aulas do curso (não misture assuntos).`,
        `Escreva perguntas curtas e claras, sem ambiguidade, usando linguagem simples.`,
        `Evite repetir estrutura ou conteúdo entre perguntas. Varie o foco e a redação.`,
        `Responda APENAS em JSON Puro no formato:`,
        `[{"question":"texto curto e objetivo","options":["A","B","C","D"],"answerIndex":0}]`,
        `Curso: ${course.title}.`,
        `Descrição: ${course.description}.`,
        `Títulos das aulas (use como base, uma por questão): ${titles.join(" | ")}.`,
      ].join("\n");
      const resp = await f("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}` },
        body: JSON.stringify({
          model: process.env.OPENAI_MODEL || "gpt-4o-mini",
          messages: [{ role: "user", content: prompt }],
          temperature: 0.2,
        }),
      });
      const data = await resp.json();
      let content = data?.choices?.[0]?.message?.content || "";
      content = content.replace(/```json|```/g, "").trim();
      try {
        const parsed = JSON.parse(content);
        if (Array.isArray(parsed)) {
          // Remover repetições por texto da questão
          const seen = new Set<string>();
          generated = parsed.filter((q: any) => {
            const key = String(q?.question || "").toLowerCase().trim();
            if (!key || seen.has(key)) return false;
            seen.add(key);
            return Array.isArray(q?.options) && q.options.length === 4 && Number.isInteger(q?.answerIndex);
          }).slice(0, 6);
        }
      } catch (e) {
        generated = null;
      }
    }
  } catch (e) {
    generated = null;
  }

  // Fallback variado e específico por palavra-chave de título
  if (!generated || !Array.isArray(generated) || generated.length === 0) {
    function byTitleToQA(t: string) {
      const tl = t.toLowerCase();
      if (tl.includes("jsx")) {
        return {
          question: "O que é JSX no React?",
          options: [
            "Uma sintaxe para escrever elementos semelhantes a HTML em JavaScript",
            "Uma biblioteca para gerenciar rotas",
            "Um servidor de desenvolvimento",
            "Um formato de banco de dados",
          ],
          answerIndex: 0,
        };
      }
      if (tl.includes("prop")) {
        return {
          question: "O que são props em React?",
          options: [
            "Valores passados aos componentes para torná-los reutilizáveis",
            "Uma função que cria estado interno",
            "Um estilo global aplicado a todos componentes",
            "Um evento disparado quando o usuário clica",
          ],
          answerIndex: 0,
        };
      }
      if (tl.includes("estado") || tl.includes("usestate")) {
        return {
          question: "O que define o estado (state) em um componente?",
          options: [
            "Informações que podem mudar ao longo do tempo no componente",
            "O layout estático da página",
            "A configuração do servidor",
            "Os arquivos de estilo",
          ],
          answerIndex: 0,
        };
      }
      if (tl.includes("useeffect")) {
        return {
          question: "Para que serve o hook useEffect?",
          options: [
            "Executar efeitos colaterais após renderizações",
            "Criar componentes de classe",
            "Declarar estilos CSS",
            "Gerenciar rotas",
          ],
          answerIndex: 0,
        };
      }
      if (tl.includes("component")) {
        return {
          question: "O que é um componente em React?",
          options: [
            "Uma função que retorna UI e pode ser reutilizada",
            "Um arquivo JSON com dados",
            "Um servidor HTTP",
            "Um pacote NPM",
          ],
          answerIndex: 0,
        };
      }
      if (tl.includes("evento") || tl.includes("event")) {
        return {
          question: "O que são eventos em React?",
          options: [
            "Ações do usuário que podemos tratar (como cliques)",
            "Bibliotecas para estilização",
            "Arquivos SVG para ícones",
            "Chamadas ao banco de dados",
          ],
          answerIndex: 0,
        };
      }
      if (tl.includes("hook")) {
        return {
          question: "Qual é a função de um hook em React?",
          options: [
            "Permitir usar estado e outras funcionalidades do React",
            "Criar rotas entre telas",
            "Instalar dependências",
            "Configurar Webpack",
          ],
          answerIndex: 0,
        };
      }
      if (tl.includes("rota") || tl.includes("router")) {
        return {
          question: "Para que serve um router em uma aplicação React?",
          options: [
            "Controlar navegação entre páginas e URLs",
            "Executar testes automatizados",
            "Compilar TypeScript",
            "Gerenciar estado global",
          ],
          answerIndex: 0,
        };
      }
      if (tl.includes("lista") || tl.includes("map")) {
        return {
          question: "Como renderizar uma lista de itens em React de forma simples?",
          options: [
            "Usando o método map para criar elementos",
            "Editando o arquivo package.json",
            "Declarando variáveis globais",
            "Chamando alert para cada item",
          ],
          answerIndex: 0,
        };
      }
      // genérico mas direto
      return {
        question: `Qual opção descreve corretamente o tópico: ${t}?`,
        options: [
          `Explicação simples e objetiva sobre ${t} no contexto do curso`,
          `Afirmação sem relação com ${t}`,
          `Ideia que contradiz o curso`,
          `Informação genérica sem utilidade prática`,
        ],
        answerIndex: 0,
      };
    }

    const base = (titles.length ? titles : vids.map(v => `Aula ${v.position || ""}`)).slice(0, 6);
    generated = base.map(byTitleToQA);
  }

  // Persistir no banco (questions/options) e retornar estrutura completa
  const inserted: { id: number; text: string; options: { id: number; text: string }[] }[] = [];
  for (let idx = 0; idx < generated.length; idx++) {
    const g = generated[idx];
    const qIns = await db.insert(questions).values({ courseId, text: g.question, order: idx + 1 }).returning({ id: questions.id, text: questions.text });
    const qId = qIns[0].id as number;
    const optsIns: { id: number; text: string }[] = [];
    for (let oi = 0; oi < g.options.length; oi++) {
      const text = g.options[oi];
      const correct = oi === g.answerIndex;
      const oIns = await db.insert(options).values({ questionId: qId, text, correct }).returning({ id: options.id, text: options.text });
      optsIns.push({ id: oIns[0].id as number, text: text });
    }
    inserted.push({ id: qId, text: qIns[0].text as string, options: optsIns });
  }
  return inserted;
}

app.get("/exam/:courseId", rateLimit({ windowMs: 60_000, max: 20 }), async (req, res) => {
  const courseId = Number(req.params.courseId);
  const course = (await db.select().from(courses).where(eq(courses.id, courseId)))[0];
  if (!course) return res.status(404).send("Curso não encontrado");
  const full = await generateAiQuestionsForCourse(courseId);
  full.sort(() => Math.random() - 0.5);
  res.render("exam", { course, questions: full });
});

app.post("/exam/:courseId", rateLimit({ windowMs: 60_000, max: 30 }), async (req, res) => {
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
  // Selecionar apenas as questões presentes no formulário
  const qIds = Object.keys(body)
    .filter(k => k.startsWith("q_"))
    .map(k => Number(k.replace("q_", "")))
    .filter(n => Number.isFinite(n));
  const qs = qIds.length
    ? await db.select().from(questions).where(and(eq(questions.courseId, courseId)))
    : await db.select().from(questions).where(eq(questions.courseId, courseId));
  const qsMap = new Map<number, { id:number; text:string }>();
  for (const q of qs) qsMap.set(q.id as number, q as any);
  const optsAll = await db.select().from(options);
  let correctCount = 0;
  for (const qId of qIds) {
    const q = qsMap.get(qId);
    if (!q) continue;
    const selected = Number(body[`q_${qId}`]);
    const correctOpt = optsAll.find(o => o.questionId === qId && !!(o.correct as any));
    const isCorrect = Number.isFinite(selected) && correctOpt && selected === (correctOpt.id as number);
    if (isCorrect) correctCount++;
  }
  const scorePercent = Math.round((correctCount / Math.max(qIds.length, 1)) * 100);
  const approved = scorePercent >= (course.minScorePercent as number);
  const examIns = await db.insert(exams).values({ studentId: student.id as number, courseId, scorePercent, approved, ip: req.ip }).returning({ id: exams.id });
  const examId = examIns[0].id as number;
  // Save answers
  for (const qId of qIds) {
    const selected = Number(body[`q_${qId}`]);
    const correctOpt = optsAll.find(o => o.questionId === qId && !!(o.correct as any));
    const isCorrect = Number.isFinite(selected) && correctOpt && selected === (correctOpt.id as number);
    await db.insert(answers).values({ examId, questionId: qId as number, optionId: selected || 0, correct: !!isCorrect });
  }
  if (!approved) {
    return res.render("exam_result", { course, scorePercent, approved });
  }
  // Proceed to payment
  res.render("payment", { course, scorePercent, examId });
});

// Payment
app.post("/payment/create", rateLimit({ windowMs: 60_000, max: 10 }), async (req, res) => {
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

// Payment via Mercado Pago (after exam)
app.post("/payment/create-mp", rateLimit({ windowMs: 60_000, max: 10 }), async (req, res) => {
  try {
    if (!mpPref) return res.status(400).send("Mercado Pago não configurado");
    const { examId } = req.body;
    const exam = (await db.select().from(exams).where(eq(exams.id, Number(examId))))[0];
    if (!exam) return res.status(400).send("Exame inválido");
    const course = (await db.select().from(courses).where(eq(courses.id, Number(exam.courseId))))[0];
    if (!course) return res.status(404).send("Curso não encontrado");

    const gross = course.priceCents as number;
    const fee = Math.round((gross * 20) / 100);
    const net = gross - fee;

    const trxIns = await db.insert(transactions).values({
      courseId: course.id as number,
      creatorId: course.creatorId as number,
      studentId: exam.studentId as number,
      grossCents: gross,
      platformFeeCents: fee,
      netCents: net,
      provider: "mercadopago",
      status: "pending",
    }).returning({ id: transactions.id });
    const transactionId = trxIns[0].id as number;

    const pref = await mpPref.create({
      body: {
        items: [{ title: `Certificado: ${course.title}`, quantity: 1, unit_price: Number((gross / 100).toFixed(2)), currency_id: "BRL" }],
        back_urls: {
          success: `${process.env.PUBLIC_URL || "http://localhost:3000"}/payment/success?transactionId=${transactionId}`,
          failure: `${process.env.PUBLIC_URL || "http://localhost:3000"}/payment/cancel`,
          pending: `${process.env.PUBLIC_URL || "http://localhost:3000"}/payment/cancel`,
        },
        auto_return: "approved",
        notification_url: `${process.env.PUBLIC_URL || "http://localhost:3000"}/payment/webhook-mp`,
        external_reference: String(transactionId),
        metadata: { transactionId: String(transactionId), courseId: String(course.id), studentId: String(exam.studentId), scorePercent: String(exam.scorePercent) },
      }
    });

    await db.update(transactions).set({ providerPaymentId: String(pref.id) }).where(eq(transactions.id, transactionId));

    const url = pref.init_point || pref.sandbox_init_point;
    res.json({ url });
  } catch (e) {
    console.error(e);
    res.status(500).send("Erro ao criar preferência no Mercado Pago");
  }
});

// Pagamento direto para certificado (sem exame)
app.post("/payment/create-direct", rateLimit({ windowMs: 60_000, max: 10 }), async (req, res) => {
  const { courseId, student_name, student_email } = req.body as { courseId: number; student_name?: string; student_email?: string };
  const course = (await db.select().from(courses).where(eq(courses.id, Number(courseId))))[0];
  if (!course) return res.status(404).send("Curso não encontrado");
  if (!student_name || !student_email) return res.status(400).send("Informe nome e e-mail");
  let student = (await db.select().from(students).where(eq(students.email, student_email)))[0];
  if (!student) {
    const hash = await bcrypt.hash(`${Date.now()}-${student_email}`, 10);
    const ins = await db.insert(students).values({ name: student_name, email: student_email, passwordHash: hash }).returning({ id: students.id });
    student = { id: ins[0].id } as any;
  }

  const gross = course.priceCents as number;
  const fee = Math.round((gross * 20) / 100);
  const net = gross - fee;

  const trxIns = await db.insert(transactions).values({
    courseId: course.id as number,
    creatorId: course.creatorId as number,
    studentId: student.id as number,
    grossCents: gross,
    platformFeeCents: fee,
    netCents: net,
    provider: stripe ? "stripe" : "manual",
    status: gross > 0 ? "pending" : "paid",
  }).returning({ id: transactions.id });
  const transactionId = trxIns[0].id as number;

  if (gross === 0 || !stripe) {
    await db.update(transactions).set({ status: "paid" }).where(eq(transactions.id, transactionId));
    await generateCertificate({ id: transactionId, studentId: student.id, courseId: course.id, creatorId: course.creatorId }, 100);
    return res.json({ url: `${process.env.PUBLIC_URL || "http://localhost:3000"}/payment/success?transactionId=${transactionId}` });
  }

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
    metadata: { transactionId: String(transactionId), courseId: String(course.id), studentId: String(student.id), scorePercent: String(100) },
  });

  await db.update(transactions).set({ providerPaymentId: session.id }).where(eq(transactions.id, transactionId));

  res.json({ url: session.url });
});

// Payment via Mercado Pago (direct, without exam)
app.post("/payment/create-direct-mp", rateLimit({ windowMs: 60_000, max: 10 }), async (req, res) => {
  try {
    if (!mpPref) return res.status(400).send("Mercado Pago não configurado");
    const { courseId, student_name, student_email } = req.body as { courseId: number; student_name?: string; student_email?: string };
    const course = (await db.select().from(courses).where(eq(courses.id, Number(courseId))))[0];
    if (!course) return res.status(404).send("Curso não encontrado");
    if (!student_name || !student_email) return res.status(400).send("Informe nome e e-mail");
    let student = (await db.select().from(students).where(eq(students.email, student_email)))[0];
    if (!student) {
      const hash = await bcrypt.hash(`${Date.now()}-${student_email}`, 10);
      const ins = await db.insert(students).values({ name: student_name, email: student_email, passwordHash: hash }).returning({ id: students.id });
      student = { id: ins[0].id } as any;
    }

    const gross = course.priceCents as number;
    const fee = Math.round((gross * 20) / 100);
    const net = gross - fee;

    const trxIns = await db.insert(transactions).values({
      courseId: course.id as number,
      creatorId: course.creatorId as number,
      studentId: student.id as number,
      grossCents: gross,
      platformFeeCents: fee,
      netCents: net,
      provider: "mercadopago",
      status: gross > 0 ? "pending" : "paid",
    }).returning({ id: transactions.id });
    const transactionId = trxIns[0].id as number;

    if (gross === 0) {
      await db.update(transactions).set({ status: "paid" }).where(eq(transactions.id, transactionId));
      await generateCertificate({ id: transactionId, studentId: student.id, courseId: course.id, creatorId: course.creatorId }, 100);
      return res.json({ url: `${process.env.PUBLIC_URL || "http://localhost:3000"}/payment/success?transactionId=${transactionId}` });
    }

    const pref = await mpPref.create({
      body: {
        items: [{ title: `Certificado: ${course.title}`, quantity: 1, unit_price: Number((gross / 100).toFixed(2)), currency_id: "BRL" }],
        back_urls: {
          success: `${process.env.PUBLIC_URL || "http://localhost:3000"}/payment/success?transactionId=${transactionId}`,
          failure: `${process.env.PUBLIC_URL || "http://localhost:3000"}/payment/cancel`,
          pending: `${process.env.PUBLIC_URL || "http://localhost:3000"}/payment/cancel`,
        },
        auto_return: "approved",
        notification_url: `${process.env.PUBLIC_URL || "http://localhost:3000"}/payment/webhook-mp`,
        external_reference: String(transactionId),
        metadata: { transactionId: String(transactionId), courseId: String(course.id), studentId: String(student.id), scorePercent: String(100) },
        payer: { email: student_email },
      }
    });

    await db.update(transactions).set({ providerPaymentId: String(pref.id) }).where(eq(transactions.id, transactionId));
    const url = pref.init_point || pref.sandbox_init_point;
    res.json({ url });
  } catch (e) {
    console.error(e);
    res.status(500).send("Erro ao criar preferência no Mercado Pago");
  }
});

// Preview: gerar certificado sem pagamento (apenas para testes)
app.post("/certificate/preview", rateLimit({ windowMs: 60_000, max: 10 }), async (req, res) => {
  try {
    const { courseId, student_name, student_email, scorePercent, display_student_name, display_course_title, certificateConfig } = req.body as { courseId: number; student_name?: string; student_email?: string; scorePercent?: number; display_student_name?: string; display_course_title?: string; certificateConfig?: any };
    const course = (await db.select().from(courses).where(eq(courses.id, Number(courseId))))[0];
    if (!course) return res.status(404).send("Curso não encontrado");
    const name = String(student_name || "Aluno Teste").trim();
    const email = String(student_email || `teste+${Date.now()}@example.com`).trim();
    let student = (await db.select().from(students).where(eq(students.email, email)))[0];
    if (!student) {
      const hash = await bcrypt.hash(`${Date.now()}-${email}`, 10);
      const ins = await db.insert(students).values({ name, email, passwordHash: hash }).returning({ id: students.id });
      student = { id: ins[0].id } as any;
    }

    const gross = course.priceCents as number;
    const fee = Math.round((gross * 20) / 100);
    const net = gross - fee;
    const trxIns = await db.insert(transactions).values({
      courseId: course.id as number,
      creatorId: course.creatorId as number,
      studentId: student.id as number,
      grossCents: gross,
      platformFeeCents: fee,
      netCents: net,
      provider: "test",
      status: "paid",
    }).returning({ id: transactions.id });
    const transactionId = trxIns[0].id as number;

    const score = Number.isFinite(Number(scorePercent)) ? Number(scorePercent) : 100;
    await generateCertificate({ id: transactionId, studentId: student.id, courseId: course.id, creatorId: course.creatorId, overrideStudentName: (display_student_name || name), overrideCourseTitle: (display_course_title || course.title), overrideCertificateConfig: certificateConfig || {} }, score);

    const cert = (await db.select().from(certificates).where(eq(certificates.transactionId, transactionId)))[0];
    if (!cert) return res.status(500).json({ error: "Falha ao gerar certificado" });
    const code = cert.code as string;
    const validateUrl = `${process.env.PUBLIC_URL || "http://localhost:3000"}/certificate/${code}`;
    const pdfName = path.basename(String(cert.pdfPath));
    const pdfUrl = `${process.env.PUBLIC_URL || "http://localhost:3000"}/certificados/${pdfName}`;
    res.json({ ok: true, code, validateUrl, pdfUrl });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao gerar certificado de teste" });
  }
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

// Webhook Mercado Pago
app.post("/payment/webhook-mp", async (req, res) => {
  try {
    if (!mpPay) return res.status(400).send("Mercado Pago não configurado");
    // Mercado Pago envia `type=payment` + `data.id` ou query `id`/`topic`
    const topic = (req.query.topic as string) || (req.body.type as string);
    const id = (req.query.id as string) || (req.body.data && (req.body.data.id as string));
    if (topic !== "payment" || !id) { return res.json({ received: true }); }

    const payment = await mpPay.get({ id });
    const externalRef = Number(payment.external_reference);
    const status = payment.status as string;
    if (!externalRef) return res.json({ received: true });
    const trx = (await db.select().from(transactions).where(eq(transactions.id, externalRef)))[0];
    if (!trx) return res.json({ ok: true });
    if (status === "approved") {
      await db.update(transactions).set({ status: "paid" }).where(eq(transactions.id, externalRef));
      const scorePercent = Number((payment.metadata as any)?.scorePercent) || 100;
      await generateCertificate(trx, scorePercent);
    }
    res.json({ received: true });
  } catch (e) {
    console.error(e);
    res.status(400).send(`Webhook MP error: ${(e as Error).message}`);
  }
});

async function generateCertificate(trx: any, scorePercent: number) {
  const student = (await db.select().from(students).where(eq(students.id, trx.studentId)))[0];
  const course = (await db.select().from(courses).where(eq(courses.id, trx.courseId)))[0];
  const creator = (await db.select().from(creators).where(eq(creators.id, trx.creatorId)))[0];
  const code = Math.random().toString(36).slice(2, 10);
  const pdfPath = path.join(process.cwd(), "certificados", `${code}.pdf`);

  const doc = new PDFDocument({ size: "A4", margin: 50, layout: "portrait" });
  const stream = fs.createWriteStream(pdfPath);
  doc.pipe(stream);
  // Fundo dark incondicional para evitar visual antigo em templates não-pro
  try {
    doc.save();
    doc.rect(0, 0, doc.page.width, doc.page.height).fill('#0f0f0f');
    doc.restore();
  } catch {}
  // Força o uso do template profissional 21 para padronizar o visual dark
  const templateId = 21;
  let styles: any = getTemplateStyles(templateId);
  // Apply overrides from course configuration (JSON) e do preview
  let cfg: any = {};
  try {
    cfg = course.certificateTemplateConfig ? JSON.parse(course.certificateTemplateConfig as string) : {};
  } catch {}
  const previewCfg = (trx as any)?.overrideCertificateConfig;
  if (previewCfg && typeof previewCfg === 'object') {
    cfg = { ...cfg, ...previewCfg };
  }
  styles = {
    ...styles,
    ...(cfg.headerColor ? { headerColor: cfg.headerColor } : {}),
    ...(cfg.headerTextColor ? { headerTextColor: cfg.headerTextColor } : {}),
    ...(cfg.title ? { title: cfg.title } : {}),
    ...(cfg.centered != null ? { centered: !!cfg.centered } : {}),
    ...(cfg.qrPosition === 'right' ? { qrRight: true } : cfg.qrPosition === 'left' ? { qrRight: false } : {}),
    ...(cfg.align ? { align: cfg.align } : {}),
    ...(cfg.font ? { font: cfg.font } : {}),
    ...(cfg.pro != null ? { pro: !!cfg.pro } : {}),
    ...(cfg.accentColor ? { accentColor: cfg.accentColor } : {}),
    ...(cfg.bgColor ? { bgColor: cfg.bgColor } : {}),
    ...(cfg.cardColor ? { cardColor: cfg.cardColor } : {}),
    ...(cfg.textColor ? { textColor: cfg.textColor } : {}),
    ...(cfg.borderColor ? { borderColor: cfg.borderColor } : {}),
    ...(cfg.mutedColor ? { mutedColor: cfg.mutedColor } : {}),
    ...(cfg.headerTitle ? { headerTitle: cfg.headerTitle } : {}),
    ...(cfg.watermarkText ? { watermarkText: cfg.watermarkText } : {}),
    ...(cfg.watermarkOpacity ? { watermarkOpacity: cfg.watermarkOpacity } : {}),
    ...(cfg.footerText ? { footerText: cfg.footerText } : {}),
  };
  // Usar modo profissional por padrão, permitindo desativar via config
  if (styles.pro == null) styles.pro = true;
  // Branding padrão: You Certificados
  if (!styles.title) styles.title = 'You Certificados';
  // Background/header
  if (styles.pro) {
    // Fundo escuro conforme paleta do sistema
    doc.save();
    doc.rect(0, 0, doc.page.width, doc.page.height).fill(styles.bgColor || '#0f0f0f'); // --bg
    doc.restore();

    // Borda dupla com contraste sutil (dark) seguindo --border
    doc.save();
    doc.lineWidth(2).strokeColor(styles.borderColor || 'rgba(255,255,255,0.08)'); // --border
    doc.rect(30, 30, doc.page.width - 60, doc.page.height - 60).stroke();
    doc.lineWidth(0.8).strokeColor('rgba(255,255,255,0.12)');
    doc.rect(40, 40, doc.page.width - 80, doc.page.height - 80).stroke();
    doc.restore();

    // Cabeçalho minimalista em card dark com logo e acento
    doc.save();
    doc.rect(0, 0, doc.page.width, 90).fill(styles.cardColor || '#181818'); // --card
    // Logo vetorial estilo plataforma (play dentro de pill vermelho)
    try {
      const lx = 24, ly = 28, lw = 36, lh = 24;
      doc.roundedRect(lx, ly, lw, lh, 4).fill(styles.accentColor || '#ff0000'); // --accent
      doc.fillColor(styles.textColor || '#ffffff');
      doc.polygon([lx + 14, ly + 6], [lx + 14, ly + lh - 6], [lx + lw - 8, ly + lh / 2]).fill();
    } catch {}
    // Título do cabeçalho
    doc.fillColor(styles.textColor || '#f1f1f1'); // --text
    try { doc.font('Helvetica-Bold'); } catch {}
    doc.fontSize(16).text(styles.headerTitle || 'Certificado de Conclusão', 0, 30, { align: 'center' });
    // Barra de acento sutil sob cabeçalho
    doc.rect(0, 90, doc.page.width, 3).fill(styles.accentColor || '#ff0000'); // --accent
    doc.restore();

    // Marca d'água visível para distinguir versão de teste
    try {
      doc.save();
      doc.opacity(typeof styles.watermarkOpacity === 'number' ? styles.watermarkOpacity : 0.08);
      doc.fillColor(styles.accentColor || '#ff0000'); // --accent
      try { doc.font('Helvetica-Bold'); } catch {}
      doc.fontSize(120).text(styles.watermarkText || 'PLATAFORMA', 0, doc.page.height / 2 - 80, { align: 'center' });
      doc.restore();
    } catch {}

    // Título principal em texto claro
    try { doc.font('Helvetica-Bold'); } catch {}
    doc.fillColor(styles.textColor || '#f1f1f1').fontSize(36).text('CERTIFICADO', 50, 120, { align: 'center' });
    // Rodapé de teste
    try { doc.font('Times-Roman'); } catch {}
    doc.fillColor(styles.mutedColor || '#aaaaaa').fontSize(9).text(styles.footerText || 'VERSÃO DE TESTE • YOU CERTIFICADOS', 0, doc.page.height - 32, { align: 'center' });
  } else {
    if (styles.headerColor) {
      doc.rect(0, 0, doc.page.width, 80).fill(styles.headerColor);
      doc.fillColor(styles.headerTextColor || '#000');
      if (styles.font) {
        try { doc.font(styles.font); } catch {}
      }
      doc.fontSize(28).text(styles.title || 'Certificado de Conclusão', 50, 28, { align: styles.align || 'left' });
      // Barra de acento no estilo YouTube
      doc.rect(0, 80, doc.page.width, 6).fill(styles.accentColor || '#FF0000');
      doc.fillColor('#000');
    } else {
      if (styles.font) {
        try { doc.font(styles.font); } catch {}
      }
      doc.fontSize(28).text(styles.title || 'Certificado de Conclusão', { align: styles.align || (styles.centered ? 'center' : 'left') });
      // Acento mínimo
      doc.rect(0, 60, doc.page.width, 4).fill(styles.accentColor || '#FF0000');
    }
  }

  doc.moveDown();
  // Permitir sobrescrever nomes exibidos no certificado
  const displayStudentName = (trx as any).overrideStudentName || String(student.name);
  const displayCourseTitle = (trx as any).overrideCourseTitle || String((cfg?.canonicalCourseTitle || course.title));
  const displayChannelName = String(cfg?.channelName || '').trim();
  if (styles.pro) {
    const align = styles.align || 'center';
    // Se houver bodyTextPro, usa frase personalizada (com tokens)
    if (cfg?.bodyTextPro) {
      try { doc.font('Times-Roman'); } catch {}
      const body = String(cfg.bodyTextPro)
        .replaceAll('{studentName}', displayStudentName)
        .replaceAll('{courseTitle}', displayCourseTitle)
        .replaceAll('{channelName}', displayChannelName)
        .replaceAll('{scorePercent}', String(scorePercent))
        .replaceAll('{date}', new Date().toLocaleDateString('pt-BR'))
        .replaceAll('{code}', code);
      doc.fillColor(styles.textColor || '#f1f1f1').fontSize(14).text(body, { align });
      doc.moveDown(0.8);
    } else {
      try { doc.font('Times-Roman'); } catch {}
      doc.fillColor(styles.mutedColor || '#aaaaaa').fontSize(16).text('Certificamos que', { align }); // --muted
      doc.moveDown(0.6);
      try { doc.font('Helvetica-Bold'); } catch {}
      doc.fillColor(styles.textColor || '#f1f1f1').fontSize(26).text(displayStudentName, { align }); // --text
      doc.moveDown(0.6);
      try { doc.font('Times-Roman'); } catch {}
      doc.fillColor(styles.mutedColor || '#aaaaaa').fontSize(16).text('concluiu com êxito o curso', { align }); // --muted
      doc.moveDown(0.3);
      try { doc.font('Helvetica-Bold'); } catch {}
      doc.fillColor(styles.textColor || '#f1f1f1').fontSize(20).text(displayCourseTitle, { align }); // --text
      if (displayChannelName) {
        doc.moveDown(0.3);
        try { doc.font('Times-Roman'); } catch {}
        doc.fillColor(styles.mutedColor || '#aaaaaa').fontSize(12).text(`Canal: ${displayChannelName}`, { align });
      }
      doc.moveDown(0.9);
    }
    const emitDate = new Date().toLocaleDateString('pt-BR');
    try { doc.font('Times-Roman'); } catch {}
    doc.fillColor(styles.mutedColor || '#aaaaaa').fontSize(12).text(`Emitido em ${emitDate}`, { align }); // --muted
    doc.moveDown(0.5);
    doc.fillColor(styles.mutedColor || '#aaaaaa').fontSize(11).text(`Código de validação: ${code}`, { align });
    doc.moveDown(0.3);
    const validateUrl = `${process.env.PUBLIC_URL || "http://localhost:3000"}/certificate/${code}`;
    doc.fillColor(styles.mutedColor || '#aaaaaa').fontSize(11).text(`Valide em: ${validateUrl}`, { align });
  } else {
    doc.fontSize(14);
    // Padrão sem nota: não exibir pontuação
    const defaultBody = `YOU CERTIFICADOS CERTIFICA O ALUNO TAL: ${displayStudentName}. Curso: ${displayCourseTitle}${displayChannelName ? `. Canal: ${displayChannelName}` : ''}. Data: ${new Date().toLocaleDateString('pt-BR')}. Código: ${code}.`;
    const bodyTemplate = cfg?.bodyText || defaultBody;
    const body = String(bodyTemplate)
      .replaceAll('{studentName}', displayStudentName)
      .replaceAll('{courseTitle}', displayCourseTitle)
      .replaceAll('{channelName}', displayChannelName)
      .replaceAll('{scorePercent}', String(scorePercent))
      .replaceAll('{date}', new Date().toLocaleDateString('pt-BR'))
      .replaceAll('{creatorName}', String(creator.name))
      .replaceAll('{code}', code);
    doc.text(body, { align: styles.align || (styles.centered ? 'center' : 'left') });
    doc.moveDown();
  }

  // Marca d'água suave (You Certificados) desativada no template profissional
  if (!styles.pro) {
    try {
      doc.save();
      doc.fillColor(styles.accentColor || '#FF0000');
      doc.opacity(typeof styles.watermarkOpacity === 'number' ? styles.watermarkOpacity : 0.06);
      const wm = styles.watermarkText || 'You Certificados';
      doc.fontSize(72).text(wm, 50, doc.page.height / 2 - 60, { align: 'center' });
      doc.restore();
    } catch {}
  }

  const validateUrl = `${process.env.PUBLIC_URL || "http://localhost:3000"}/certificate/${code}`;
  const qrData = await QRCode.toDataURL(validateUrl);
  const qrBase64 = qrData.split(",")[1];
  const qrBuf = Buffer.from(qrBase64, "base64");
  if (styles.qrRight) {
    const fit = styles.pro ? [98, 98] : [120, 120];
    const x = styles.pro ? (doc.page.width - 150) : (doc.page.width - 170);
    const y = styles.pro ? (doc.page.height - 190) : (doc.page.height - 220);
    doc.image(qrBuf, x, y, { fit });
    if (styles.pro) {
      try { doc.font('Times-Roman'); } catch {}
      doc.fillColor(styles.mutedColor || '#aaaaaa').fontSize(9).text('Escaneie para validar', x - 8, y + (fit[1] as number) + 8, { width: 120, align: 'center' });
    }
  } else {
    doc.image(qrBuf, { fit: styles.pro ? [98, 98] : [120, 120], align: "left" });
  }

  // Assinatura
  if (styles.pro) {
    const sigY = doc.page.height - 140;
    doc.strokeColor(styles.borderColor || 'rgba(255,255,255,0.08)').lineWidth(1); // --border
    doc.moveTo(70, sigY).lineTo(doc.page.width / 2 - 40, sigY).stroke();
    // Imagem de assinatura, se configurada
    if (cfg?.signaturePath) {
      const pSig = path.join(process.cwd(), String(cfg.signaturePath).replace(/^\//, ''));
      try { doc.image(pSig, 70, sigY - 46, { fit: [160, 48] }); } catch {}
    }
    // Nome da assinatura, se configurado
    if (cfg?.signatureName) {
      try { doc.font('Times-Roman'); } catch {}
      doc.fillColor(styles.textColor || '#f1f1f1').fontSize(12).text(String(cfg.signatureName), 70, sigY - 18, { align: 'left' });
    }
    try { doc.font('Times-Roman'); } catch {}
    doc.fillColor(styles.mutedColor || '#aaaaaa').fontSize(10).text('Assinatura do responsável', 70, sigY + 6, { align: 'left' });
  } else if (cfg?.signatureName) {
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

  // Selo no template profissional
  if (styles.pro) {
    const sealX = 90;
    const sealY = doc.page.height - 240;
    doc.save();
    doc.circle(sealX, sealY, 24).fill(styles.sealColor || styles.accentColor || '#dc2626');
    try { doc.font('Helvetica-Bold'); } catch {}
    doc.fillColor('#fff').fontSize(12).text('YOU', sealX - 16, sealY - 8, { width: 32, align: 'center' });
    doc.restore();
  }

  doc.end();
  // Garantir que o arquivo foi totalmente gravado antes de salvar/retornar
  await new Promise<void>((resolve, reject) => {
    try {
      stream.on("finish", () => resolve());
      stream.on("error", (err) => reject(err));
    } catch (e) {
      resolve();
    }
  });

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
    // Template profissional
    21: { title: 'Certificado', centered: true, qrRight: true, align: 'center', pro: true, sealColor: '#dc2626' }
  };
  return presets[id] || presets[21];
}

// Certificate validation
app.get("/certificate/:code", async (req, res) => {
  const code = req.params.code;
  const cert = (await db.select().from(certificates).where(eq(certificates.code, code)))[0];
  if (!cert) return res.render("certificate_validated", { valid: false });
  const course = (await db.select().from(courses).where(eq(courses.id, cert.courseId)))[0];
  const student = (await db.select().from(students).where(eq(students.id, cert.studentId)))[0];
  const pdfName = path.basename(String(cert.pdfPath));
  res.render("certificate_validated", { valid: true, cert, course, student, pdfName });
});

// Fluxo simplificado: sem dashboard de aluno

// Minimal pages for success/cancel
app.get("/payment/success", (req, res) => {
  res.render("payment_success");
});
app.get("/payment/cancel", (req, res) => {
  res.render("payment_cancel");
});

// Página de validação de certificado (entrada de código)
app.get("/certificate/validate", (req, res) => {
  res.render("certificate_validate", { title: "Validar certificado" });
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
app.get("/creator/course/:id/questions", requireCreator, async (req, res) => res.status(404).send("Indisponível"));
// Certificate template selection
app.get("/creator/course/:id/certificate-template", requireCreator, async (req, res) => res.status(404).send("Indisponível"));

app.post("/creator/course/:id/certificate-template", requireCreator, async (req, res) => res.status(404).send("Indisponível"));

// Certificate editor (configurable templates)
app.get("/creator/course/:id/certificate-editor", requireCreator, async (req, res) => res.status(404).send("Indisponível"));

app.post("/creator/course/:id/certificate-editor", requireCreator, async (req, res) => res.status(404).send("Indisponível"));