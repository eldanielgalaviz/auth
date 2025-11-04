import { 
  Controller, 
  Post, 
  Body, 
  UseGuards, 
  Get, 
  Req,
  ForbiddenException,
  NotFoundException,
  Logger 
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto } from './dtos/auth.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { Roles } from './decorators/roles.decorator';
import { UserRole } from './interfaces/user.interface';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('register-first-admin')
  async registerFirstAdmin(@Body() registerDto: RegisterDto) {
    return this.authService.registerFirstAdmin(registerDto);
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Req() req) {
    const { password, ...userWithoutPassword } = req.user;
    return userWithoutPassword;
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Post('promote-to-admin')
  async promoteToAdmin(
    @Body('userId') userId: string, 
    @Req() req
  ) {
    const adminUser = req.user;
    if (adminUser.role !== UserRole.ADMIN) {
      throw new ForbiddenException('Solo un administrador puede realizar esta acción');
    }

    const userToPromote = this.authService.getUserById(userId);
    if (!userToPromote) {
      throw new NotFoundException('Usuario no encontrado');
    }

    return this.authService.changeUserRole(userId, UserRole.ADMIN);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Get('admin')
  getAdminPanel() {
    return { message: 'Bienvenido al panel de administración' };
  }
}
