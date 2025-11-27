import { sqliteTable, text, integer, blob } from "drizzle-orm/sqlite-core";
import { sql } from "drizzle-orm";

export const creators = sqliteTable("creators", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  name: text("name").notNull(),
  email: text("email").unique().notNull(),
  passwordHash: text("password_hash").notNull(),
  commissionPercent: integer("commission_percent").notNull().default(20),
  createdAt: integer("created_at").notNull().default(sql`unixepoch()`),
});

export const students = sqliteTable("students", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  name: text("name").notNull(),
  email: text("email").unique().notNull(),
  passwordHash: text("password_hash").notNull(),
  createdAt: integer("created_at").notNull().default(sql`unixepoch()`),
});

export const courses = sqliteTable("courses", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  creatorId: integer("creator_id").notNull().references(() => creators.id),
  title: text("title").notNull(),
  description: text("description").notNull(),
  playlistUrl: text("playlist_url"),
  priceCents: integer("price_cents").notNull(),
  workloadMinutes: integer("workload_minutes"),
  slug: text("slug").unique().notNull(),
  minScorePercent: integer("min_score_percent").notNull().default(70),
  attemptsAllowed: integer("attempts_allowed"),
  certificateTemplateId: integer("certificate_template_id"),
  certificateTemplateConfig: text("certificate_template_config"),
  createdAt: integer("created_at").notNull().default(sql`unixepoch()`),
});

export const questions = sqliteTable("questions", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  courseId: integer("course_id").notNull().references(() => courses.id),
  text: text("text").notNull(),
  order: integer("order"),
});

export const options = sqliteTable("options", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  questionId: integer("question_id").notNull().references(() => questions.id),
  text: text("text").notNull(),
  correct: integer("correct", { mode: "boolean" }).notNull().default(false),
});

// Exam attempts
export const exams = sqliteTable("exams", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  studentId: integer("student_id").notNull().references(() => students.id),
  courseId: integer("course_id").notNull().references(() => courses.id),
  scorePercent: integer("score_percent").notNull(),
  approved: integer("approved", { mode: "boolean" }).notNull().default(false),
  attemptsCount: integer("attempts_count").notNull().default(1),
  ip: text("ip"),
  createdAt: integer("created_at").notNull().default(sql`unixepoch()`),
});

export const answers = sqliteTable("answers", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  examId: integer("exam_id").notNull().references(() => exams.id),
  questionId: integer("question_id").notNull().references(() => questions.id),
  optionId: integer("option_id").notNull().references(() => options.id),
  correct: integer("correct", { mode: "boolean" }).notNull().default(false),
});

export const transactions = sqliteTable("transactions", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  courseId: integer("course_id").notNull().references(() => courses.id),
  creatorId: integer("creator_id").notNull().references(() => creators.id),
  studentId: integer("student_id").notNull().references(() => students.id),
  grossCents: integer("gross_cents").notNull(),
  platformFeeCents: integer("platform_fee_cents").notNull(),
  netCents: integer("net_cents").notNull(),
  provider: text("provider").notNull(),
  providerPaymentId: text("provider_payment_id"),
  status: text("status").notNull(), // pending/paid/failed
  createdAt: integer("created_at").notNull().default(sql`unixepoch()`),
});

export const certificates = sqliteTable("certificates", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  transactionId: integer("transaction_id").notNull().references(() => transactions.id),
  code: text("code").unique().notNull(),
  pdfPath: text("pdf_path").notNull(),
  studentId: integer("student_id").notNull().references(() => students.id),
  courseId: integer("course_id").notNull().references(() => courses.id),
  scorePercent: integer("score_percent").notNull(),
  createdAt: integer("created_at").notNull().default(sql`unixepoch()`),
});

// Videos da playlist do curso
export const courseVideos = sqliteTable("course_videos", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  courseId: integer("course_id").notNull().references(() => courses.id),
  videoId: text("video_id").notNull(),
  position: integer("position"),
});

// Progresso por sessão (cookie) e vídeo
export const progress = sqliteTable("progress", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  sessionId: text("session_id").notNull(),
  courseId: integer("course_id").notNull().references(() => courses.id),
  videoId: text("video_id").notNull(),
  watchedSeconds: integer("watched_seconds").notNull().default(0),
  durationSeconds: integer("duration_seconds").notNull().default(0),
  completed: integer("completed", { mode: "boolean" }).notNull().default(false),
  updatedAt: integer("updated_at").notNull().default(sql`unixepoch()`),
});