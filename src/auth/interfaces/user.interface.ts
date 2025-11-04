// En interfaces/user.interface.ts
export enum UserRole {
  GUEST = 'guest',
  USER = 'user',
  ADMIN = 'admin'
}

export interface User {
  id: string;
  username: string;
  email: string;
  password: string;
  role: UserRole;
}