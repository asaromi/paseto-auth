import { BadRequestError } from "./exceptions.ts";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// min 8 chars, 1 upper, 1 lower, 1 digit, 1 special
const PASSWORD_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,72}$/;
const NAME_RE = /^[a-zA-Z\u00C0-\u017F' -]{2,100}$/; // letters, accents, space, hyphen, apostrophe

export const validateEmail = (email: unknown): string => {
  if (!email) {
    throw new BadRequestError("Email is required");
  } else if (typeof email !== "string" || !EMAIL_RE.test(email.trim())) {
    throw new BadRequestError("Invalid email format");
  }

  return email.trim().toLowerCase();
};

export const validatePassword = (password: unknown): string => {
  if (!password) {
    throw new BadRequestError("Password is required");
  } else if (typeof password !== "string" || !PASSWORD_RE.test(password)) {
    throw new BadRequestError(
      "Password must be 8-72 chars, with upper/lowercase, number and special character",
    );
  }
  return password;
};

export const validateFullName = (fullName: unknown): string => {
  if (typeof fullName !== "string" || !NAME_RE.test(fullName.trim())) {
    throw new BadRequestError("Invalid full name format");
  }
  return fullName.trim();
};
