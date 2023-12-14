import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';

type mailOptions = {
  subject: string;
  name: string;
  email: string;
  activationCode: string;
  template: string;
};
@Injectable()
export class EmailService {
  constructor(private mailService: MailerService) {}
  async sendMail({
    subject,
    name,
    email,
    activationCode,
    template,
  }: mailOptions) {
    await this.mailService.sendMail({
      to: email,
      subject,
      template,
      context: {
        name,
        activationCode,
      },
    });
  }
}
