# app.py
import os
from functools import wraps
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

# --- INIT ---
load_dotenv()  # Lädt .env-Datei
app = Flask(__name__)

# --- CONFIG ---
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "fallback_dev_key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///dreamforge.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["WTF_CSRF_ENABLED"] = False  # Für Entwicklung: Tokens deaktiviert

# --- EXTENSIONS ---
db = SQLAlchemy(app)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)

login_manager.login_view = "login"
login_manager.login_message_category = "warning"

# --- MODELS ---
user_permission_groups = db.Table(
    "user_permission_groups",
    db.Column("user_id", db.Integer, db.ForeignKey(
        "user.id"), primary_key=True),
    db.Column(
        "permission_group_id",
        db.Integer,
        db.ForeignKey("permission_group.id"),
        primary_key=True,
    ),
)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    first_login = db.Column(db.Boolean, default=True)
    permission_groups = db.relationship(
        "PermissionGroup", secondary=user_permission_groups, back_populates="users"
    )

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def has_permission(self, group_name):
        return any(group.name == group_name for group in self.permission_groups)


class PermissionGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    users = db.relationship(
        "User", secondary=user_permission_groups, back_populates="permission_groups"
    )


class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    required_permission = db.Column(db.String(50))  # String-Name der Gruppe
    template_file = db.Column(db.String(100), nullable=True)


# --- LOGIN MANAGER ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- HELPERS ---
def get_service_id(name):
    """Gibt die ID eines Service anhand seines Namens zurück."""
    s = Service.query.filter_by(name=name).first()
    return s.id if s else None


def flash_redirect(message, category, service_name):
    """Kombinierter Flash + Redirect zum Service."""
    flash(message, category)
    sid = get_service_id(service_name)
    return redirect(url_for("service_page", service_id=sid))


def get_accessible_services(user):
    """Filtert Services nach Benutzerrechten."""
    all_services = Service.query.order_by(Service.name).all()
    if not user or not user.is_authenticated:
        return [s for s in all_services if not s.required_permission]
    return [
        s
        for s in all_services
        if not s.required_permission or user.has_permission(s.required_permission)
    ]


# --- CONTEXT PROCESSOR ---
@app.context_processor
def inject_services():
    try:
        services = get_accessible_services(current_user)
    except Exception:
        services = []
    home = Service.query.filter_by(name="Home").first()
    home_service_id = home.id if home else None
    return dict(services=services, home_service_id=home_service_id)


# --- DECORATORS ---
def permission_required(*allowed_groups):
    """Decorator für Service-/Routenberechtigungen."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Bitte logge dich ein.", "danger")
                return redirect(url_for("login"))
            if not any(current_user.has_permission(g) for g in allowed_groups):
                flash("Keine Berechtigung.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- ROUTES ---
@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    home = Service.query.filter_by(name="Home").first()
    if home:
        return redirect(url_for("service_page", service_id=home.id))
    flash("Home-Service nicht gefunden.", "warning")
    return render_template("dashboard.html", active_page="dashboard")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        remember = True if request.form.get("remember") else False
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=remember)
            if user.first_login:
                return redirect(url_for("change_password"))
            return redirect(url_for("dashboard"))
        flash("Falscher Benutzername oder Passwort", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        new_password = request.form["password"]
        current_user.set_password(new_password)
        current_user.first_login = False
        db.session.commit()
        flash("Passwort erfolgreich geändert!", "success")
        return redirect(url_for("dashboard"))
    return render_template("change_password.html")


@app.route("/systemmanager/update_user/<int:user_id>", methods=["POST"])
@login_required
@permission_required("superadmin")
def update_user_inline(user_id):
    u = User.query.get_or_404(user_id)

    # Superadmin darf nicht umbenannt werden
    if u.username == "superadmin":
        return flash_redirect("Der Superadmin darf nicht bearbeitet werden!", "danger", "User Control")

    u.username = request.form["username"]
    group_names = request.form.getlist("groups")
    u.permission_groups = []
    for name in group_names:
        group = PermissionGroup.query.filter_by(name=name).first()
        if group:
            u.permission_groups.append(group)
    db.session.commit()
    return flash_redirect("Benutzer aktualisiert!", "success", "User Control")


@app.route("/systemmanager/delete_user/<int:user_id>", methods=["POST"])
@login_required
@permission_required("superadmin")
def delete_user_inline(user_id):
    u = User.query.get_or_404(user_id)

    # Superadmin darf nicht gelöscht werden
    if u.username == "superadmin":
        return flash_redirect("Der Superadmin kann nicht gelöscht werden!", "danger", "User Control")

    db.session.delete(u)
    db.session.commit()
    return flash_redirect("Benutzer gelöscht!", "success", "User Control")


@app.route("/systemmanager/add_user", methods=["POST"])
@login_required
@permission_required("superadmin")
def add_user_inline():
    username = request.form["username"]
    password = request.form["password"]
    group_names = request.form.getlist("groups")

    if User.query.filter_by(username=username).first():
        return flash_redirect("Benutzername existiert bereits.", "danger", "User Control")

    u = User(username=username)
    u.set_password(password)
    for name in group_names:
        group = PermissionGroup.query.filter_by(name=name).first()
        if group:
            u.permission_groups.append(group)
    db.session.add(u)
    db.session.commit()
    return flash_redirect("Benutzer hinzugefügt!", "success", "User Control")


# --- SYSTEMMANAGER: PERMISSION CONTROL ---
@app.route("/systemmanager/add_group", methods=["POST"])
@login_required
@permission_required("superadmin")
def add_group_inline():
    name = request.form["name"]
    if PermissionGroup.query.filter_by(name=name).first():
        return flash_redirect("Gruppe existiert bereits!", "danger", "Permission Control")
    db.session.add(PermissionGroup(name=name))
    db.session.commit()
    return flash_redirect("Gruppe hinzugefügt!", "success", "Permission Control")


@app.route("/systemmanager/update_group/<int:group_id>", methods=["POST"])
@login_required
@permission_required("superadmin")
def update_group_inline(group_id):
    g = PermissionGroup.query.get_or_404(group_id)

    # Superadmin-Gruppe darf nicht umbenannt werden
    if g.name == "superadmin":
        return flash_redirect("Die Superadmin-Gruppe darf nicht bearbeitet werden!", "danger", "Permission Control")

    g.name = request.form["name"]
    db.session.commit()
    return flash_redirect("Gruppe aktualisiert!", "success", "Permission Control")


@app.route("/systemmanager/delete_group/<int:group_id>", methods=["POST"])
@login_required
@permission_required("superadmin")
def delete_group_inline(group_id):
    g = PermissionGroup.query.get_or_404(group_id)

    # Superadmin-Gruppe darf nicht gelöscht werden
    if g.name == "superadmin":
        return flash_redirect("Die Superadmin-Gruppe kann nicht gelöscht werden!", "danger", "Permission Control")

    db.session.delete(g)
    db.session.commit()
    return flash_redirect("Gruppe gelöscht!", "success", "Permission Control")

# --- SYSTEMMANAGER: SERVICE CONTROL ---


@app.route("/systemmanager/add_service", methods=["POST"])
@login_required
@permission_required("superadmin")
def add_service_inline():
    name = request.form.get("name")
    description = request.form.get("description")
    required_permission = request.form.get("required_permission") or None
    template_file = request.form.get("template_file") or None

    if not name:
        return flash_redirect("Service-Name darf nicht leer sein.", "danger", "Service Control")

    if Service.query.filter_by(name=name).first():
        return flash_redirect("Service existiert bereits!", "danger", "Service Control")

    s = Service(
        name=name,
        description=description,
        required_permission=required_permission,
        template_file=template_file,
    )
    db.session.add(s)
    db.session.commit()
    return flash_redirect("Service hinzugefügt!", "success", "Service Control")


@app.route("/systemmanager/update_service/<int:service_id>", methods=["POST"])
@login_required
@permission_required("superadmin")
def update_service_inline(service_id):
    s = Service.query.get_or_404(service_id)

    # Sperre für kritische Services
    if s.name in ("Home", "User Control", "Permission Control", "Service Control"):
        flash("Dieser Service darf nicht bearbeitet werden!", "danger")
        return redirect(url_for("service_page", service_id=s.id))

    s.name = request.form["name"]
    s.description = request.form.get("description", "")
    s.required_permission = request.form.get("required_permission") or None
    s.template_file = request.form.get("template_file") or None
    db.session.commit()
    flash("Service aktualisiert!", "success")
    return redirect(url_for("service_page", service_id=s.id))


@app.route("/systemmanager/delete_service/<int:service_id>", methods=["POST"])
@login_required
@permission_required("superadmin")
def delete_service_inline(service_id):
    s = Service.query.get_or_404(service_id)

    # Sperre für kritische Services
    if s.name in ("Home", "User Control", "Permission Control", "Service Control"):
        flash("Dieser Service kann nicht gelöscht werden!", "danger")
        return redirect(url_for("service_page", service_id=s.id))

    db.session.delete(s)
    db.session.commit()
    flash("Service gelöscht!", "success")
    return redirect(url_for("service_page", service_id=get_service_id("Service Control")))


# --- SERVICE PAGES ---
@app.route("/services/<int:service_id>")
@login_required
def service_page(service_id):
    service = Service.query.get_or_404(service_id)
    if service.required_permission and not current_user.has_permission(service.required_permission):
        flash("Du hast keine Berechtigung für diesen Dienst.", "danger")
        return redirect(url_for("dashboard"))

    template_to_render = (
        f"services/{service.template_file}" if service.template_file else "service.html"
    )

    context = {"service": service, "active_page": f"service_{service.id}"}
    if service.name in ("User Control", "Permission Control", "Service Control") and not current_user.has_permission("superadmin"):
        flash("Du hast keine Berechtigung für diesen Dienst.", "danger")
        return redirect(url_for("dashboard"))
    if service.name == "User Control":
        context["users"] = User.query.all()
        context["all_groups"] = PermissionGroup.query.all()
    elif service.name == "Permission Control":
        context["all_groups"] = PermissionGroup.query.all()
    elif service.name == "Service Control":
        context["all_services"] = Service.query.order_by(Service.name).all()
        context["all_groups"] = PermissionGroup.query.all()

    return render_template(template_to_render, **context)


@app.route("/service_editor/<int:service_id>", methods=["GET", "POST"])
@login_required
@permission_required("superadmin")
def service_editor(service_id):
    service = Service.query.get_or_404(service_id)
    template_path = os.path.join(
        "templates", "services", service.template_file or "")

    if request.method == "POST":
        new_content = request.form["html_content"]
        with open(template_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        flash("Template gespeichert!", "success")
        return redirect(url_for("service_page", service_id=service.id))

    html_content = ""
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            html_content = f.read()

    return render_template(
        "service_editor.html",
        service=service,
        html_content=html_content
    )


# --- APP STARTUP ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        for svc_name in ("User Control", "Permission Control", "Service Control"):
            s = Service.query.filter_by(name=svc_name).first()
            if s and s.required_permission != "superadmin":
                s.required_permission = "superadmin"
        db.session.commit()
        # Superadmin Gruppe
        superadmin_group = PermissionGroup.query.filter_by(
            name="superadmin").first()
        if not superadmin_group:
            superadmin_group = PermissionGroup(name="superadmin")
            db.session.add(superadmin_group)
            db.session.commit()

        # Superadmin User
        superadmin_user = User.query.filter_by(username="superadmin").first()
        if not superadmin_user:
            superadmin_user = User(username="superadmin")
            superadmin_user.set_password("supersecret")
            superadmin_user.permission_groups.append(superadmin_group)
            db.session.add(superadmin_user)
            db.session.commit()
            print("Superadmin erstellt: Benutzername=superadmin Passwort=supersecret")

        # Standard-Services
        default_services = [
            ("Home", "Startseite (Home) als Service.", None, "home.html"),
            (
                "User Control",
                "Zentraler Verwaltungsdienst für Benutzerverwaltung.",
                "superadmin",
                "user_control.html",
            ),
            (
                "Permission Control",
                "Verwaltung der Berechtigungsgruppen.",
                "superadmin",
                "permission_control.html",
            ),
            (
                "Service Control",
                "Verwaltung der registrierten Services.",
                "superadmin",
                "service_control.html",
            ),
        ]

        for name, desc, perm, tmpl in default_services:
            if not Service.query.filter_by(name=name).first():
                db.session.add(Service(name=name, description=desc,
                               required_permission=perm, template_file=tmpl))
        db.session.commit()

    app.run(debug=False)
