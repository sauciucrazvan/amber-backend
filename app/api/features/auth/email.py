import os

from fastapi import BackgroundTasks
import resend

resend.api_key = os.getenv("RESEND_API_KEY")


def enqueue_email(background_tasks: BackgroundTasks, payload: dict) -> None:
    background_tasks.add_task(resend.Emails.send, payload) # type: ignore


def build_amber_email_html(
    *,
    title: str,
    preheader: str,
    full_name: str,
    username: str,
    body_html: str,
    otp_code: str | None = None,
    otp_label: str = "One-time code",
    footer_note: str = "This is an automated Amber notification.",
) -> str:
    otp_block = ""
    if otp_code:
        otp_block = f"""
                    <br /><br />
                    <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color: #f9fafb; border: 1px solid #e5e7eb; border-radius: 10px;\">
                        <tr>
                            <td align=\"center\" style=\"padding: 12px 16px 6px 16px; font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.08em;\">
                                {otp_label}
                            </td>
                        </tr>
                        <tr>
                            <td align=\"center\" style=\"padding: 0 16px 14px 16px; font-size: 32px; font-weight: 700; color: #111827; letter-spacing: 0.24em; font-family: 'Courier New', Courier, monospace;\">
                                {otp_code}
                            </td>
                        </tr>
                    </table>
                """.strip()

    return f"""
                <!doctype html>
                <html>
                    <head>
                        <meta charset=\"UTF-8\" />
                        <title>{title}</title>
                        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
                    </head>
                    <body style=\"margin: 0; padding: 0; background-color: #f4f6f8; font-family: Arial, Helvetica, sans-serif;\">
                        <div style=\"display: none; max-height: 0; overflow: hidden; opacity: 0; color: transparent;\">
                            {preheader}
                        </div>

                        <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color: #f4f6f8; padding: 40px 0;\">
                            <tr>
                                <td align=\"center\">
                                    <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"max-width: 520px; background: #ffffff; border-radius: 12px; padding: 40px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);\">
                                        <tr>
                                            <td align=\"center\" style=\"padding-bottom: 24px;\">
                                                <img src=\"https://web.amber.razvansauciuc.dev/amber.png\" width=\"96\" height=\"96\" alt=\"Amber Logo\" style=\"display: block; border-radius: 20px;\" />
                                                <div style=\"font-size: 22px; font-weight: bold; margin-top: 12px; color: #222;\">Amber</div>
                                            </td>
                                        </tr>

                                        <tr>
                                            <td style=\"font-size: 15px; color: #333333; line-height: 1.6;\">
                                                Hello, <strong>{full_name}</strong> (<span style=\"color: #6b7280\">@{username}</span>).
                                                <br /><br />
                                                {body_html}
                                                {otp_block}
                                            </td>
                                        </tr>

                                        <tr>
                                            <td style=\"padding: 28px 0 12px 0;\">
                                                <hr style=\"border: none; border-top: 1px solid #e5e7eb;\" />
                                            </td>
                                        </tr>

                                        <tr>
                                            <td align=\"center\" style=\"font-size: 13px; color: #9ca3af;\">
                                                <strong style=\"color: #374151\">The Amber Team</strong><br />
                                                {footer_note}
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                    </body>
                </html>
        """.strip()
