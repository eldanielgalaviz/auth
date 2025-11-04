import { 
  Injectable, 
  UnauthorizedException, 
  ForbiddenException, 
  NotFoundException,
  Logger 
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User, UserRole, JwtPayload } from './interfaces/user.interface';
import { RegisterDto, LoginDto } from './dtos/auth.dto';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private users: User[] = [];

  constructor(
    private jwtService: JwtService,
    private configService: ConfigService
  ) {
    this.initializeAdminUser();
  }

  hasAdmin(): boolean {
    return this.users.some(user => user.role === UserRole.ADMIN);
  }

  private async initializeAdminUser() {
    if (!this.hasAdmin()) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      const adminUser: User = {
        id: 'admin_1',
        username: 'admin',
        email: 'admin@example.com',
        password: hashedPassword,
        role: UserRole.ADMIN
      };

      this.users.push(adminUser);
      this.logger.log('Usuario administrador predeterminado creado');
    }
  }

  async register(registerDto: RegisterDto): Promise<User> {
    const existingUser = this.users.find(u => u.email === registerDto.email);
    if (existingUser) {
      throw new ForbiddenException('El email ya está registrado');
    }

    const hashedPassword = await bcrypt.hash(registerDto.password, 10);
    
    const newUser: User = {
      id: `user_${this.users.length + 1}`,
      username: registerDto.username,
      email: registerDto.email,
      password: hashedPassword,
      role: registerDto.role || UserRole.GUEST
    };

    this.users.push(newUser);
    
    const { password, ...userWithoutPassword } = newUser;
    return userWithoutPassword as User;
  }

  async registerFirstAdmin(registerDto: RegisterDto): Promise<User> {
    if (this.hasAdmin()) {
      throw new ForbiddenException('Ya existe un usuario administrador');
    }

    const existingUser = this.users.find(u => u.email === registerDto.email);
    if (existingUser) {
      throw new ForbiddenException('El email ya está registrado');
    }

    const hashedPassword = await bcrypt.hash(registerDto.password, 10);
    
    const adminUser: User = {
      id: `admin_${this.users.length + 1}`,
      username: registerDto.username,
      email: registerDto.email,
      password: hashedPassword,
      role: UserRole.ADMIN
    };

    this.users.push(adminUser);
    
    const { password, ...userWithoutPassword } = adminUser;
    return userWithoutPassword as User;
  }

  async login(loginDto: LoginDto): Promise<{ access_token: string, user: User }> {
    const user = this.users.find(u => u.email === loginDto.email);
    
    if (!user || !(await bcrypt.compare(loginDto.password, user.password))) {
      throw new UnauthorizedException('Credenciales inválidas');
    }

    // Cambiar rol de GUEST a USER si es necesario
    if (user.role === UserRole.GUEST) {
      user.role = UserRole.USER;
    }

    const payload: JwtPayload = { 
      sub: user.id, 
      username: user.username, 
      role: user.role
    };

    const secret = this.configService.get('JWT_SECRET') || 'tu_secreto_super_seguro_2024';
    const expiresIn = this.configService.get('JWT_EXPIRATION') || '1h';

    return {
      access_token: this.jwtService.sign(payload, { 
        secret: secret,
        expiresIn: expiresIn 
      }),
      user: {
        ...user,
        password: undefined
      }
    };
  }

  async validateUser(payload: JwtPayload): Promise<User | null> {
    return this.users.find(user => user.id === payload.sub);
  }

  changeUserRole(userId: string, newRole: UserRole): User {
    const user = this.users.find(u => u.id === userId);
    
    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    user.role = newRole;
    return user;
  }

  getUserById(userId: string): User | undefined {
    return this.users.find(u => u.id === userId);
  }
}