import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,  // Elimina propiedades no definidas en el DTO
    forbidNonWhitelisted: false, // Permite propiedades adicionales
    transform: true,  // Convierte los datos al tipo definido en el DTO
    validationError: {
      target: false,  // No incluir el objeto completo en el error
      value: false   // No incluir el valor que causó el error
    }
  }));

  app.enableCors(); // Habilitar CORS si no está habilitado

  await app.listen(3000);
  console.log('Aplicación corriendo en http://localhost:3000');
}
bootstrap();