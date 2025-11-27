import { sqlite } from "../src/db";

// Simple programmatic migrations to keep MVP straightforward
const statements = [
  `CREATE TABLE IF NOT EXISTS creators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    commission_percent INTEGER NOT NULL DEFAULT 20,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  )`,
  `CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  )`,
  `CREATE TABLE IF NOT EXISTS enrollments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL REFERENCES students(id),
    course_id INTEGER NOT NULL REFERENCES courses(id),
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  )`,
  `CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    creator_id INTEGER NOT NULL REFERENCES creators(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    playlist_url TEXT,
    price_cents INTEGER NOT NULL,
    workload_minutes INTEGER,
    slug TEXT NOT NULL UNIQUE,
    min_score_percent INTEGER NOT NULL DEFAULT 70,
    attempts_allowed INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  )`,
  `CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER NOT NULL REFERENCES courses(id),
    text TEXT NOT NULL,
    "order" INTEGER
  )`,
  `CREATE TABLE IF NOT EXISTS options (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id INTEGER NOT NULL REFERENCES questions(id),
    text TEXT NOT NULL,
    correct INTEGER NOT NULL DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS exams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL REFERENCES students(id),
    course_id INTEGER NOT NULL REFERENCES courses(id),
    score_percent INTEGER NOT NULL,
    approved INTEGER NOT NULL DEFAULT 0,
    attempts_count INTEGER NOT NULL DEFAULT 1,
    ip TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  )`,
  `CREATE TABLE IF NOT EXISTS answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exam_id INTEGER NOT NULL REFERENCES exams(id),
    question_id INTEGER NOT NULL REFERENCES questions(id),
    option_id INTEGER NOT NULL REFERENCES options(id),
    correct INTEGER NOT NULL DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER NOT NULL REFERENCES courses(id),
    creator_id INTEGER NOT NULL REFERENCES creators(id),
    student_id INTEGER NOT NULL REFERENCES students(id),
    gross_cents INTEGER NOT NULL,
    platform_fee_cents INTEGER NOT NULL,
    net_cents INTEGER NOT NULL,
    provider TEXT NOT NULL,
    provider_payment_id TEXT,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  )`,
  `CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id INTEGER NOT NULL REFERENCES transactions(id),
    code TEXT NOT NULL UNIQUE,
    pdf_path TEXT NOT NULL,
    student_id INTEGER NOT NULL REFERENCES students(id),
    course_id INTEGER NOT NULL REFERENCES courses(id),
    score_percent INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  )`
  ,
  `CREATE TABLE IF NOT EXISTS course_videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER NOT NULL REFERENCES courses(id),
    video_id TEXT NOT NULL,
    position INTEGER
  )`
  ,
  `CREATE TABLE IF NOT EXISTS progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    course_id INTEGER NOT NULL REFERENCES courses(id),
    video_id TEXT NOT NULL,
    watched_seconds INTEGER NOT NULL DEFAULT 0,
    duration_seconds INTEGER NOT NULL DEFAULT 0,
    completed INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
  )`
];

for (const stmt of statements) {
  sqlite.prepare(stmt).run();
}

// Add columns if missing (best-effort)
try {
  const cols = sqlite.prepare(`PRAGMA table_info(courses)`).all() as any[];
  const hasTemplate = cols.some(c => c.name === "certificate_template_id");
  if (!hasTemplate) {
    sqlite.prepare(`ALTER TABLE courses ADD COLUMN certificate_template_id INTEGER`).run();
    console.log("Added column courses.certificate_template_id");
  }
  const hasTemplateConfig = cols.some(c => c.name === "certificate_template_config");
  if (!hasTemplateConfig) {
    sqlite.prepare(`ALTER TABLE courses ADD COLUMN certificate_template_config TEXT`).run();
    console.log("Added column courses.certificate_template_config");
  }
} catch (e) {
  // ignore
}

console.log("SQLite migrated: tables ensured.");