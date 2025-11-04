import { IsEmail, IsNotEmpty, MinLength, IsOptional } from 'class-validator';
import { UserRole } from '../interfaces/user.interface';

export class RegisterDto {
  @IsNotEmpty({ message: 'El nombre de usuario no puede estar vacío' })
  username: string;

  @IsEmail({}, { message: 'Formato de email inválido' })
  email: string;

  @IsNotEmpty({ message: 'La contraseña no puede estar vacía' })
  @MinLength(4, { message: 'La contraseña debe tener al menos 4 caracteres' }) // Reducir longitud mínima
  password: string;

  @IsOptional()
  role?: UserRole = UserRole.GUEST;
}

export class LoginDto {
  @IsEmail({}, { message: 'Formato de email inválido' })
  email: string;

  @IsNotEmpty({ message: 'La contraseña no puede estar vacía' })
  password: string;
}