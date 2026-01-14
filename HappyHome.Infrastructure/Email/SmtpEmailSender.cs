using System.Net;
using System.Net.Mail;
using HappyHome.Application.Auth;
using HappyHome.Application.Auth.Abstractions;
using Microsoft.Extensions.Options;

namespace HappyHome.Infrastructure.Email
{
    public class SmtpEmailSender : IEmailSender
    {
        private readonly IConfiguration _config;
        private readonly JwtOptions _opt;

        public SmtpEmailSender(IConfiguration config, IOptions<JwtOptions> opt)
        {
            _config = config;
            _opt = opt.Value;
        }

        public async Task SendAsync(string toEmail, string subject, string htmlBody, CancellationToken ct = default)
        {
            // Config section Email:Smtp...
            var host = _config["Email:SmtpHost"] ?? "";
            var port = int.TryParse(_config["Email:SmtpPort"], out var p) ? p : 587;
            var user = _config["Email:SmtpUser"];
            var pass = _config["Email:SmtpPass"];
            var enableSsl = !string.Equals(_config["Email:EnableSsl"], "false", StringComparison.OrdinalIgnoreCase);

            // Dev fallback: nếu chưa config SMTP, log ra console để test nhanh
            if (string.IsNullOrWhiteSpace(host))
            {
                Console.WriteLine("==== EMAIL (DEV) ====");
                Console.WriteLine($"To: {toEmail}");
                Console.WriteLine($"Subject: {subject}");
                Console.WriteLine(htmlBody);
                Console.WriteLine("=====================");
                return;
            }

            using var msg = new MailMessage();
            msg.From = new MailAddress(_opt.MailFrom);
            msg.To.Add(toEmail);
            msg.Subject = subject;
            msg.Body = htmlBody;
            msg.IsBodyHtml = true;

            using var client = new SmtpClient(host, port);
            client.EnableSsl = enableSsl;

            if (!string.IsNullOrWhiteSpace(user))
                client.Credentials = new NetworkCredential(user, pass);

            await client.SendMailAsync(msg, ct);
        }
    }
}
