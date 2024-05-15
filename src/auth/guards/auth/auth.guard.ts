import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { AuthService } from 'src/auth/auth.service';


@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService, private authService: AuthService) {}
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

  async canActivate(context: ExecutionContext):  Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException();
    }
    try {
      const payload = await this.jwtService.verifyAsync(token, { secret: process.env.JWT_SECRET });      
       
      const user = await this.authService.findUserById(payload.id);
      if ( !user ) throw new UnauthorizedException('User does not exists');

      request['user'] = user;      
    } catch {
      throw new UnauthorizedException();
    }
    return true;
  }

}
