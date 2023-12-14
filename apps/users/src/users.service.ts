import {
  BadGatewayException,
  BadRequestException,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService, JwtVerifyOptions } from '@nestjs/jwt';
import {
  ActivationDto,
  ForgotPasswordDto,
  LoginDto,
  RegisterDto,
  ResetPasswordDto,
} from './dto/user.dto';
import { PrismaService } from '../../../prisma/Prisma.service';
import { Response } from 'express';
import * as bcrypt from 'bcryptjs';
import { EmailService } from './email/email.service';
import { TokenSender } from './utils/jwt';
import { User } from '@prisma/client';

interface UserData {
  name: string;
  email: string;
  password: string;
  phone_number: number;
}

@Injectable()
export class UsersService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly mailService: EmailService,
  ) {}

  // register user
  async register(registerDto: RegisterDto, response: Response) {
    const { name, email, phone_number, password } = registerDto;
    const isEmailExist = await this.prisma.user.findUnique({
      where: { email },
    });

    if (isEmailExist) {
      throw new BadGatewayException('Email already exist for this email');
    }

    const isPhoneNumberExist = await this.prisma.user.findUnique({
      where: { phone_number },
    });

    if (isPhoneNumberExist) {
      throw new BadGatewayException(
        'User exist with this phone number, try another number',
      );
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
      name,
      email,
      phone_number,
      password: hashedPassword,
    };

    const activationToken = await this.creatActivationToken(user);

    const activationCode = activationToken.activationCode;

    const activation_token = activationToken.token;

    await this.mailService.sendMail({
      name,
      email,
      subject: 'Activate your account',
      template: './activation-mail',
      activationCode,
    });

    return { activation_token, response };
  }

  // activate  user
  async activateUser(activationDto: ActivationDto, response: Response) {
    const { activationToken, activationCode } = activationDto;

    const newUser: { user: UserData; activationCode: string } =
      this.jwtService.verify(activationToken, {
        secret: this.configService.get<string>('ACTIVATION_SECRET'),
      } as JwtVerifyOptions) as { user: UserData; activationCode: string };

    if (newUser.activationCode !== activationCode) {
      throw new BadGatewayException('Invalid activation code');
    }

    const { email, name, phone_number, password } = newUser.user;

    const isEmailExist = await this.prisma.user.findUnique({
      where: { email },
    });

    if (isEmailExist) {
      throw new BadGatewayException('Email already exist for this email');
    }

    const user = await this.prisma.user.create({
      data: {
        name,
        email,
        phone_number,
        password,
      },
    });

    return { user, response };
  }

  // activation code
  async creatActivationToken(user: UserData) {
    const activationCode = Math.floor(1000 + Math.random() * 9000).toString();

    const token = this.jwtService.sign(
      {
        user,
        activationCode,
      },
      {
        secret: this.configService.get<string>('ACTIVATION_SECRET'),
        expiresIn: '5m',
      },
    );
    return { activationCode, token };
  }

  // login user
  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;

    const user = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });
    if (user && (await this.comparePassword(password, user.password))) {
      const tokenSender = new TokenSender(this.configService, this.jwtService);
      return tokenSender.SendToken(user);
    } else {
      return {
        user: null,
        accessToken: null,
        refreshToken: null,
        error: {
          message: 'Invalid email or password',
        },
      };
    }
  }

  // compare password
  async comparePassword(
    password: string,
    hashPassword: string,
  ): Promise<boolean> {
    return await bcrypt.compare(password, hashPassword);
  }

  // get logged in user
  async getLoggedInUser(req: any) {
    const user = req.user;
    const accessToken = req.accesstoken;
    const refreshToken = req.refreshtoken;

    return { user, accessToken, refreshToken };
  }

  // user logged
  async getLoggedOutUser(req: any) {
    req.user = null;
    req.accesstoken = null;
    req.refreshtoken = null;
    return { message: 'Logout successfully' };
  }

  // generate forgot password link
  async generateForgotPasswordLink(user: User) {
    const forgotPasswordToken = this.jwtService.sign(
      {
        user,
      },
      {
        secret: this.configService.get<string>('FORGOT_PASSWORD_SECRET'),
        expiresIn: '5m',
      },
    );
    return forgotPasswordToken;
  }

  // forgot password
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const { email } = forgotPasswordDto;
    const user = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      throw new BadRequestException('User not found with this email!');
    }
    const forgotPasswordToken = await this.generateForgotPasswordLink(user);

    const resetPasswordUrl =
      this.configService.get<string>('CLIENT_SIDE_URI') +
      `/reset-password?verify=${forgotPasswordToken}`;

    await this.mailService.sendMail({
      email,
      subject: 'Reset your Password!',
      template: './forgot-password',
      name: user.name,
      activationCode: resetPasswordUrl,
    });

    return { message: `Your forgot password request succesful!` };
  }

  // reset password
  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const { password, activationToken } = resetPasswordDto;

    const decoded = await this.jwtService.decode(activationToken);

    if (!decoded || decoded?.exp * 1000 < Date.now()) {
      throw new BadRequestException('Invalid token!');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.prisma.user.update({
      where: {
        id: decoded.user.id,
      },
      data: {
        password: hashedPassword,
      },
    });

    return { user };
  }

  // get all user services
  async getUser() {
    return this.prisma.user.findMany({});
  }
}
