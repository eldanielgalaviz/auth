import { IsEmail, IsNotEmpty, MinLength, IsOptional } from 'class-validator';
import { UserRole } from '../interfaces/user.interface';

export class RegisterDto {
  @IsNotEmpty({ message: 'El nombre de usuario no puede estar vacío' })
  username: string;

  @IsEmail({}, { message: 'Formato de email inválido' })
  email: string;

  @IsNotEmpty({ message: 'La contraseña no puede estar vacía' })
  @MinLength(8, { message: 'La contraseña debe tener al menos 8 caracteres' })
  password: string;

  @IsOptional() // Permite que la propiedad role sea opcional
  role?: UserRole = UserRole.GUEST;
}

export class LoginDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  password: string;
}
