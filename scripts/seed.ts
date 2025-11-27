import { db } from "../src/db";
import { creators, courses, questions, options } from "../src/schema";
import { eq } from "drizzle-orm";
import bcrypt from "bcrypt";

async function main() {
  const email = "demo@creator.com";
  const name = "Demo Creator";
  const passwordHash = await bcrypt.hash("demo123", 10);

  const existing = await db.select().from(creators).where(eq(creators.email, email));
  let creatorId: number;
  if (existing.length === 0) {
    const inserted = await db.insert(creators).values({
      email,
      name,
      passwordHash,
      commissionPercent: 20,
    }).returning({ id: creators.id });
    creatorId = inserted[0].id as number;
  } else {
    creatorId = existing[0].id as number;
  }

  const slug = "curso-demo-youtube";
  const existingCourse = await db.select().from(courses).where(eq(courses.slug, slug));
  let courseId: number;
  if (existingCourse.length === 0) {
    const inserted = await db.insert(courses).values({
      creatorId,
      title: "Curso Demo YouTube",
      description: "Aprenda conceitos básicos com vídeos da playlist demo.",
      playlistUrl: "https://www.youtube.com/playlist?list=PL_DEMO",
      priceCents: 2990,
      workloadMinutes: 120,
      slug,
      minScorePercent: 70,
      attemptsAllowed: 3,
    }).returning({ id: courses.id });
    courseId = inserted[0].id as number;
  } else {
    courseId = existingCourse[0].id as number;
  }

  const q1 = await db.insert(questions).values({ courseId, text: "Qual é a capital do Brasil?", order: 1 }).returning({ id: questions.id });
  const q2 = await db.insert(questions).values({ courseId, text: "Quanto é 2 + 2?", order: 2 }).returning({ id: questions.id });

  await db.insert(options).values([
    { questionId: q1[0].id as number, text: "São Paulo", correct: false },
    { questionId: q1[0].id as number, text: "Rio de Janeiro", correct: false },
    { questionId: q1[0].id as number, text: "Brasília", correct: true },
    { questionId: q2[0].id as number, text: "3", correct: false },
    { questionId: q2[0].id as number, text: "4", correct: true },
    { questionId: q2[0].id as number, text: "5", correct: false },
  ]);

  console.log("Seed concluído: criador demo, curso demo e perguntas adicionadas.");
}

main();