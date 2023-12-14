import { MailerModule } from '@nestjs-modules/mailer';
import { EjsAdapter } from '@nestjs-modules/mailer/dist/adapters/ejs.adapter';
import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { join } from 'path';
import { EmailService } from './email.service';

@Global()
@Module({
  imports: [
    MailerModule.forRootAsync({
      useFactory: async (config: ConfigService) => ({
        transport: {
          host: config.get('SMTP_HOST'),
          port: config.get('587'),
          secure: true,
          auth: {
            user: config.get('SMTP_MAIL'),
            pass: config.get('SMTP_PASSWORD'),
          },
          tls: {
            rejectUnauthorized: false,
          },
        },
        defaults: {
          from: 'FoodMat',
        },
        template: {
          dir: join(__dirname, '../../../../servers/email-templates'),
          adapter: new EjsAdapter(),
          options: {
            strict: false,
          },
        },
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [EmailService],
})
export class EmailModule {}
