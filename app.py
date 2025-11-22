import os
import html
import logging
from flask import Flask, request, render_template, flash, redirect, url_for
from flask_wtf import FlaskForm, CSRFProtect, RecaptchaField
from wtforms import StringField, TextAreaField, BooleanField, IntegerField, RadioField, SelectField
from wtforms.validators import DataRequired, Email, Length, NumberRange, Regexp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, ReplyTo
from dotenv import load_dotenv
from flask_talisman import Talisman
import bleach
from email_validator import validate_email, EmailNotValidError
from werkzeug.middleware.proxy_fix import ProxyFix

# --- Load Environment Variables ---
load_dotenv()

# --- Flask Setup ---
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY must be set in environment!")

# --- HTTPS behind reverse proxy ---
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# --- CSRF Protection ---
csrf = CSRFProtect(app)

# --- Session & Cookie Security ---
app.config.update(
    SESSION_COOKIE_SECURE=True,
    REMEMBER_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    WTF_CSRF_TIME_LIMIT=3600,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024  # 2MB max
)

# --- Recaptcha ---
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv("RECAPTCHA_SITE_KEY")
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv("RECAPTCHA_SECRET_KEY")

# --- Rate Limiting ---
limiter = Limiter(key_func=get_remote_address, default_limits=["10 per minute"])
limiter.init_app(app)

# --- Logging Setup ---
SENSITIVE_FIELDS = {"first_name", "last_name", "email", "information"}

class FormDataFilter(logging.Filter):
    """Sanitize sensitive form data before logging."""
    def filter(self, record):
        if hasattr(record, "form_data") and isinstance(record.form_data, dict):
            sanitized = {}
            for key, value in record.form_data.items():
                if key in SENSITIVE_FIELDS:
                    sanitized[key] = "***MASKED***"
                else:
                    sanitized[key] = html.escape(str(value))
            record.form_data = sanitized
        return True

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger()
logger.addFilter(FormDataFilter())

# --- Security Headers (Talisman) ---
csp = {
    'default-src': ["'self'"],
    'script-src': [
        "'self'",
        "https://www.google.com/recaptcha/",
        "https://www.gstatic.com/recaptcha/"
    ],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", "data:"],
    'frame-src': ["https://www.google.com/recaptcha/"],
    'connect-src': ["'self'"]
}

is_production = os.getenv("FLASK_ENV") == "production"

Talisman(
    app,
    content_security_policy=csp,
    strict_transport_security=is_production,
    strict_transport_security_max_age=63072000,
    strict_transport_security_include_subdomains=is_production,
    strict_transport_security_preload=is_production,
    referrer_policy='no-referrer',
    frame_options='DENY',
    force_https=is_production
)

# --- Add Security Header: X-Content-Type-Options ---
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers["Server"] = ""
    return response

# --- Form Definition ---
class SubmissionForm(FlaskForm):
    first_name = StringField(
        'First Name',
        validators=[DataRequired(), Length(max=50), Regexp(r"^[A-Za-z\s'-]+$", message="Invalid characters in name")]
    )
    last_name = StringField(
        'Last Name',
        validators=[DataRequired(), Length(max=50), Regexp(r"^[A-Za-z\s'-]+$", message="Invalid characters in name")]
    )
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=100)])
    product_type = RadioField(
        'Product Type',
        choices=[('personal','Personal'), ('business','Business')],
        validators=[DataRequired()]
    )
    age = IntegerField('Age', validators=[NumberRange(min=13, max=120)], filters=[lambda x: x or None])
    referrer = SelectField(
        'Referrer',
        choices=[('', '(Select one)'), ('News', 'News'), ('YouTube', 'YouTube'), ('Forum', 'Forum'), ('Other', 'Other')]
    )
    information = TextAreaField('Information', validators=[DataRequired(), Length(max=2000)])
    terms = BooleanField('Terms and Conditions', validators=[DataRequired()])
    recaptcha = RecaptchaField()

# --- HTTPS Redirect ---
@app.before_request
def enforce_https_in_production():
    if is_production:
        if not request.is_secure and request.headers.get("X-Forwarded-Proto", "http") != "https":
            url = request.url.replace("http://", "https://", 1)
            return redirect(url, code=301)

# --- Helpers ---
def validate_email_address(email: str) -> bool:
    try:
        v = validate_email(email)
        email_clean = v.email
        if '\r' in email_clean or '\n' in email_clean:
            return False
        return True
    except EmailNotValidError:
        return False

def sanitize_input(value: str, allow_html=False) -> str:
    if not value:
        return ""
    value = value.strip()
    if allow_html:
        allowed_tags = ['b','i','u','em','strong','p','br','ul','li','ol']
        return bleach.clean(value, tags=allowed_tags, attributes={}, strip=True)
    return html.escape(value)

def sanitize_for_email(value: str) -> str:
    if not value:
        return ""
    return html.escape(value.strip())

# --- Routes ---
@app.route('/', methods=['GET'])
def index():
    form = SubmissionForm()
    return render_template('form.html', form=form)

@app.route('/send', methods=['POST'])
@limiter.limit("5 per minute")
def send_email():
    form = SubmissionForm()
    if not form.validate_on_submit():
        flash("❌ Please check your input and try again.", "error")
        return redirect(url_for('index'))

    # Sanitize input
    first_name = sanitize_for_email(form.first_name.data)
    last_name = sanitize_for_email(form.last_name.data)
    user_email = sanitize_for_email(form.email.data)
    if not validate_email_address(user_email):
        flash("❌ Invalid email address.", "error")
        return redirect(url_for('index'))

    product_type = sanitize_for_email(form.product_type.data)
    age = form.age.data if form.age.data else "N/A"
    referrer = sanitize_for_email(form.referrer.data)
    information_display = sanitize_input(form.information.data, allow_html=True)
    information_email = sanitize_for_email(form.information.data)
    terms = "Accepted" if form.terms.data else "Not accepted"

    # Log safely
    logger.info("Form submission received", extra={"form_data": {
        "first_name": first_name,
        "last_name": last_name,
        "email": user_email,
        "product_type": product_type,
        "age": age,
        "referrer": referrer,
        "information": information_email,
        "terms": terms
    }})

    try:
        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))

        # Email to user
        mail_user = Mail(
            from_email=os.getenv("FROM_EMAIL"),
            to_emails=user_email,
            subject="Welcome!",
            plain_text_content=f"Hello {first_name},\n\nYour submission was received successfully."
        )
        mail_user.reply_to = ReplyTo(os.getenv("FROM_EMAIL"))
        sg.send(mail_user)

        # Email to admin (truncate info)
        info_truncated = (information_email[:1000] + "...") if len(information_email) > 1000 else information_email
        mail_admin = Mail(
            from_email=os.getenv("FROM_EMAIL"),
            to_emails=os.getenv("ADMIN_EMAIL"),
            subject="New Form Submission",
            plain_text_content=(f"New form submission:\n\n"
                                f"First Name: {first_name}\n"
                                f"Last Name: {last_name}\n"
                                f"Email: {user_email}\n"
                                f"Product Type: {product_type}\n"
                                f"Age: {age}\n"
                                f"Referrer: {referrer}\n"
                                f"Information: {info_truncated}\n"
                                f"Accepted Terms: {terms}\n")
        )
        mail_admin.reply_to = ReplyTo(os.getenv("FROM_EMAIL"))
        sg.send(mail_admin)

        return render_template("form_completed.html", information=information_display)

    except Exception:
        logger.exception("Email sending failed")
        flash("❌ Internal server error. Please try again later.", "error")
        return redirect(url_for('index'))

# --- Error Handling ---
@app.errorhandler(429)
def ratelimit_handler(e):
    return "Too many requests. Please try again later.", 429

@app.errorhandler(500)
def internal_error(e):
    return "Internal server error. Please try again later.", 500

# --- Main ---
if __name__ == '__main__':
    debug = not is_production
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=debug)



