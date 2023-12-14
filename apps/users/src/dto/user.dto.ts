import { Field, InputType } from '@nestjs/graphql';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

@InputType()
export class RegisterDto {
  @Field()
  @IsNotEmpty({ message: 'Name is required.' })
  @IsString({ message: 'Name must be string.' })
  name: string;

  @Field()
  @IsNotEmpty({ message: 'Password is required.' })
  @MinLength(8, { message: 'Password must be atleast 8 characters.' })
  password: string;

  @Field()
  @IsNotEmpty({ message: 'Email is required.' })
  @IsEmail({}, { message: 'Email is valid.' })
  email: string;

  @Field()
  @IsNotEmpty({ message: 'Phone number is required.' })
  phone_number: number;
}

@InputType()
export class ActivationDto {
  @Field()
  @IsNotEmpty({ message: 'Activation Token is required.' })
  activationToken: string;

  @Field()
  @IsNotEmpty({ message: 'Activation code is required.' })
  activationCode: string;
}

@InputType()
export class LoginDto {
  @Field()
  @IsNotEmpty({ message: 'Email is required.' })
  @IsEmail({}, { message: 'Email is valid.' })
  email: string;

  @Field()
  @IsNotEmpty({ message: 'Password is required.' })
  password: string;
}
@InputType()
export class ForgotPasswordDto {
  @Field()
  @IsNotEmpty({ message: 'Email is required.' })
  @IsEmail({}, { message: 'Email is valid.' })
  email: string;
}

@InputType()
export class ResetPasswordDto {
  @Field()
  @IsNotEmpty({ message: 'Password is required.' })
  @MinLength(8, { message: 'Password must be at least 8 characters.' })
  password: string;

  @Field()
  @IsNotEmpty({ message: 'Activation Token is required.' })
  activationToken: string;
}
