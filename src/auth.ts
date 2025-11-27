import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";

export type TokenPayload = {
  id: number;
  role: "creator" | "student";
  name: string;
  email: string;
};

export const signToken = (payload: TokenPayload) => {
  const secret = process.env.JWT_SECRET || "devsecret";
  return jwt.sign(payload, secret, { expiresIn: "7d" });
};

export const verifyToken = (token?: string) => {
  try {
    const secret = process.env.JWT_SECRET || "devsecret";
    if (!token) return null;
    return jwt.verify(token, secret) as TokenPayload;
  } catch {
    return null;
  }
};

export const requireCreator = (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies?.creator_token as string | undefined;
  const payload = verifyToken(token);
  if (!payload || payload.role !== "creator") return res.status(401).send("Não autorizado");
  (req as any).user = payload;
  next();
};

export const requireStudent = (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies?.student_token as string | undefined;
  const payload = verifyToken(token);
  if (!payload || payload.role !== "student") return res.status(401).send("Não autorizado");
  (req as any).user = payload;
  next();
};