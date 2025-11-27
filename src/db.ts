import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import fs from "fs";
import path from "path";

const dbFile = path.resolve("data.db");
if (!fs.existsSync(dbFile)) {
  fs.writeFileSync(dbFile, "");
}

export const sqlite = new Database(dbFile);
export const db = drizzle(sqlite);