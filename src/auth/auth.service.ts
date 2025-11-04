import { Injectable, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User, UserRole, JwtPayload } from './interfaces/user.interface';
import { RegisterDto, LoginDto } from './dtos/auth.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  private users: User[] = [];

  constructor(private jwtService: JwtService) {}

  async register(registerDto: RegisterDto): Promise<User> {
    // Verificar si el email ya existe
    const existingUser = this.users.find(u => u.email === registerDto.email);
    if (existingUser) {
      throw new ForbiddenException('El email ya está registrado');
    }

    // Hashear la contraseña
    const hashedPassword = await bcrypt.hash(registerDto.password, 10);
    
    // Crear nuevo usuario
    const newUser: User = {
      id: `user_${this.users.length + 1}`,
      username: registerDto.username,
      email: registerDto.email,
      password: hashedPassword,
      role: registerDto.role || UserRole.GUEST
    };

    this.users.push(newUser);
    
    // Eliminar la contraseña antes de devolver
    const { password, ...userWithoutPassword } = newUser;
    return userWithoutPassword as User;
  }

  async login(loginDto: LoginDto): Promise<{ access_token: string, user: User }> {
    const user = this.users.find(u => u.email === loginDto.email);
    
    if (!user || !(await bcrypt.compare(loginDto.password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload: JwtPayload = { 
      sub: user.id, 
      username: user.username, 
      role: user.role
    };

    return {
      access_token: this.jwtService.sign(payload),
      user: user
    };
  }

  async validateUser(payload: JwtPayload): Promise<User | null> {
    return this.users.find(user => user.id === payload.sub);
  }
}