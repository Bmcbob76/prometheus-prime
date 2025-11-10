"""RED TEAM - Phishing Campaigns
AUTHORIZED USE ONLY - For penetration testing and security awareness training
"""
import logging
import smtplib
import uuid
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger("PROMETHEUS-PRIME.RedTeam.Phishing")

class PhishingCampaign:
    """Phishing simulation for security awareness training"""

    def __init__(self, scope_validator=None, authorization_required=True):
        self.logger = logger
        self.authorization_required = authorization_required
        self.scope_validator = scope_validator
        self.campaigns = {}
        self.templates = self._load_templates()
        self.logger.info("PhishingCampaign module initialized - SECURITY AWARENESS TRAINING ONLY")

    def _check_authorization(self, target: str, method: str) -> bool:
        if not self.authorization_required:
            return True
        if self.scope_validator:
            authorized = self.scope_validator.validate(target, method)
            if not authorized:
                raise PermissionError(f"Target not in authorized scope")
            return True
        self.logger.warning("No scope validator - assuming authorized")
        return True

    def _load_templates(self) -> Dict[str, str]:
        """Load phishing email templates"""
        return {
            "password_reset": {
                "subject": "Urgent: Password Reset Required",
                "body": """Dear User,

We have detected unusual activity on your account. For security purposes, please reset your password immediately by clicking the link below:

{link}

This link will expire in 24 hours.

Thank you,
IT Security Team
"""
            },
            "hr_document": {
                "subject": "Important: Updated Employee Handbook",
                "body": """Hello,

Please review the updated employee handbook attached below:

{link}

All employees must acknowledge receipt by end of week.

Best regards,
Human Resources
"""
            },
            "ceo_urgent": {
                "subject": "URGENT - Action Required",
                "body": """I need you to handle something urgently. Can you process this request?

{link}

Time sensitive.

Thanks
"""
            }
        }

    def create_campaign(self, campaign_name: str, template: str, target_list: List[str],
                       tracking_domain: str = "tracking.local") -> Dict[str, Any]:
        """Create a phishing simulation campaign"""
        self._check_authorization("campaign", "create")

        campaign_id = str(uuid.uuid4())
        tracking_links = {}

        for target_email in target_list:
            user_id = str(uuid.uuid4())[:8]
            tracking_links[target_email] = f"https://{tracking_domain}/track/{campaign_id}/{user_id}"

        self.campaigns[campaign_id] = {
            "name": campaign_name,
            "template": template,
            "targets": target_list,
            "tracking_links": tracking_links,
            "created": datetime.now().isoformat(),
            "status": "created",
            "clicks": [],
            "submissions": []
        }

        return {
            "method": "create_campaign",
            "status": "created",
            "campaign_id": campaign_id,
            "targets_count": len(target_list),
            "tracking_domain": tracking_domain
        }

    def send_phishing_email(self, campaign_id: str, smtp_server: str, from_email: str,
                           from_password: str = None) -> Dict[str, Any]:
        """Send phishing emails for security awareness testing"""
        self._check_authorization("email", "send")

        if campaign_id not in self.campaigns:
            return {"method": "send_email", "status": "failed", "error": "Campaign not found"}

        campaign = self.campaigns[campaign_id]
        template = self.templates.get(campaign["template"])

        if not template:
            return {"method": "send_email", "status": "failed", "error": "Template not found"}

        sent_count = 0
        failed = []

        for target_email, tracking_link in campaign["tracking_links"].items():
            try:
                msg = MIMEMultipart()
                msg['From'] = from_email
                msg['To'] = target_email
                msg['Subject'] = template["subject"]

                body = template["body"].format(link=tracking_link)
                msg.attach(MIMEText(body, 'plain'))

                with smtplib.SMTP(smtp_server, 25, timeout=10) as server:
                    if from_password:
                        server.starttls()
                        server.login(from_email, from_password)
                    server.send_message(msg)

                sent_count += 1

            except Exception as e:
                failed.append({"email": target_email, "error": str(e)})

        self.campaigns[campaign_id]["status"] = "sent"

        return {
            "method": "send_phishing_email",
            "status": "complete",
            "campaign_id": campaign_id,
            "sent": sent_count,
            "failed": len(failed),
            "failures": failed[:5]
        }

    def track_click(self, campaign_id: str, user_id: str) -> Dict[str, Any]:
        """Track when a user clicks a phishing link"""
        if campaign_id not in self.campaigns:
            return {"status": "campaign_not_found"}

        self.campaigns[campaign_id]["clicks"].append({
            "user_id": user_id,
            "timestamp": datetime.now().isoformat()
        })

        return {"status": "click_tracked", "campaign_id": campaign_id}

    def generate_landing_page(self, page_type: str = "credential_harvest") -> Dict[str, Any]:
        """Generate phishing landing page HTML"""
        self._check_authorization("landing_page", "generate")

        if page_type == "credential_harvest":
            html = """<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
<h2>Please Login</h2>
<form method="POST" action="/harvest">
    <input type="text" name="username" placeholder="Username" required><br>
    <input type="password" name="password" placeholder="Password" required><br>
    <button type="submit">Login</button>
</form>
</body>
</html>"""
        else:
            html = "<html><body><h1>Page Not Found</h1></body></html>"

        return {
            "method": "generate_landing_page",
            "status": "generated",
            "page_type": page_type,
            "html": html
        }

    def get_campaign_stats(self, campaign_id: str) -> Dict[str, Any]:
        """Get statistics for a phishing campaign"""
        if campaign_id not in self.campaigns:
            return {"status": "not_found"}

        campaign = self.campaigns[campaign_id]
        targets_count = len(campaign["targets"])
        clicks_count = len(campaign["clicks"])
        click_rate = (clicks_count / targets_count * 100) if targets_count > 0 else 0

        return {
            "campaign_id": campaign_id,
            "campaign_name": campaign["name"],
            "targets": targets_count,
            "clicks": clicks_count,
            "click_rate": round(click_rate, 2),
            "submissions": len(campaign["submissions"]),
            "status": campaign["status"]
        }

    def get_capabilities(self) -> List[str]:
        return ["create_campaign", "send_phishing_email", "track_click", "generate_landing_page", "get_campaign_stats"]

__all__ = ["PhishingCampaign"]
