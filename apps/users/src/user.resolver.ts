import { BadRequestException, UseGuards } from '@nestjs/common';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import {
  ActivationDto,
  ForgotPasswordDto,
  RegisterDto,
  ResetPasswordDto,
} from './dto/user.dto';

import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import { Response } from 'express';
import {
  ActivationResponseType,
  ForgotPasswordResponseType,
  LoginResponseType,
  LogoutResponseType,
  RegisterResponseType,
  ResetPasswordResponseType,
} from './types/user.types';
import { AuthGuard } from './guards/auth.guard';

@Resolver('User')
export class UsersResolver {
  constructor(private readonly userService: UsersService) {}

  @Mutation(() => RegisterResponseType)
  async register(
    @Args('registerDto') registerDto: RegisterDto,
    @Context() context: { res: Response },
  ): Promise<RegisterResponseType> {
    if (!registerDto.email || !registerDto.name || !registerDto.password) {
      throw new BadRequestException('Please fill all the fields');
    }
    const { activation_token } = await this.userService.register(
      registerDto,
      context.res,
    );

    return { activation_token };
  }

  @Mutation(() => ActivationResponseType)
  async activateUser(
    @Args('activationDto') activationDto: ActivationDto,
    @Context() context: { res: Response },
  ): Promise<ActivationResponseType> {
    return await this.userService.activateUser(activationDto, context.res);
  }

  @Mutation(() => LoginResponseType)
  async login(
    @Args('email') email: string,
    @Args('password') password: string,
  ): Promise<LoginResponseType> {
    return await this.userService.login({ email, password });
  }

  @Query(() => LoginResponseType)
  @UseGuards(AuthGuard)
  async getLoggedInUser(@Context() context: { req: Request }) {
    return await this.userService.getLoggedInUser(context.req);
  }

  @Query(() => LogoutResponseType)
  @UseGuards(AuthGuard)
  async getLoggedOutUser(@Context() context: { req: Request }) {
    return await this.userService.getLoggedOutUser(context.req);
  }

  @Mutation(() => ForgotPasswordResponseType)
  async forgotPassword(
    @Args('forgotPasswordDto') forgotPasswordDto: ForgotPasswordDto,
  ): Promise<ForgotPasswordResponseType> {
    return await this.userService.forgotPassword(forgotPasswordDto);
  }

  @Mutation(() => ResetPasswordResponseType)
  async resetPassword(
    @Args('resetPasswordDto') resetPasswordDto: ResetPasswordDto,
  ): Promise<ResetPasswordResponseType> {
    return await this.userService.resetPassword(resetPasswordDto);
  }

  @Query(() => [User])
  async getUsers() {
    return this.userService.getUser();
  }
}
