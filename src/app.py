# app.py
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
from functools import wraps

app = Flask(__name__)
app.config["SECRET_KEY"] = "super_strong_secret_key_here"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///dreamforge.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# --- MODELS ---
user_permission_groups = db.Table(
    "user_permission_groups",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
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
    required_permission = db.Column(db.String(50))  # None = für alle
    template_file = db.Column(db.String(100), nullable=True)  # optionales Service-Template

# --- LOGIN MANAGER ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Hilfsfunktion: Services, die der aktuelle User sehen darf ---
def get_accessible_services(user):
    all_services = Service.query.order_by(Service.name).all()
    if not user or not user.is_authenticated:
        return [s for s in all_services if not s.required_permission]
    return [s for s in all_services if not s.required_permission or user.has_permission(s.required_permission)]

# --- Kontext Processor: services und home_service_id ---
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
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Bitte logge dich ein.", "danger")
                return redirect(url_for("login"))
            if not any(current_user.has_permission(group) for group in allowed_groups):
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

# --- SystemManager User Control Inline Actions ---
@app.route("/systemmanager/update_user/<int:user_id>", methods=["POST"])
@login_required
@permission_required("superadmin")
def update_user_inline(user_id):
    u = User.query.get_or_404(user_id)
    u.username = request.form["username"]
    group_names = request.form.getlist("groups")
    u.permission_groups = []
    for name in group_names:
        group = PermissionGroup.query.filter_by(name=name).first()
        if group:
            u.permission_groups.append(group)
    db.session.commit()
    flash("Benutzer aktualisiert!", "success")
    service_id = Service.query.filter_by(name="User Control").first().id
    return redirect(url_for("service_page", service_id=service_id))

@app.route("/systemmanager/delete_user/<int:user_id>", methods=["POST"])
@login_required
@permission_required("superadmin")
def delete_user_inline(user_id):
    u = User.query.get_or_404(user_id)
    db.session.delete(u)
    db.session.commit()
    flash("Benutzer gelöscht!", "success")
    service_id = Service.query.filter_by(name="User Control").first().id
    return redirect(url_for("service_page", service_id=service_id))

@app.route("/systemmanager/add_user", methods=["POST"])
@login_required
@permission_required("superadmin")
def add_user_inline():
    username = request.form["username"]
    password = request.form["password"]
    group_names = request.form.getlist("groups")
    if User.query.filter_by(username=username).first():
        flash("Benutzername existiert bereits.", "danger")
    else:
        u = User(username=username)
        u.set_password(password)
        for name in group_names:
            group = PermissionGroup.query.filter_by(name=name).first()
            if group:
                u.permission_groups.append(group)
        db.session.add(u)
        db.session.commit()
        flash("Benutzer hinzugefügt!", "success")
    service_id = Service.query.filter_by(name="User Control").first().id
    return redirect(url_for("service_page", service_id=service_id))

# --- SystemManager Permission Control Inline Actions ---
@app.route("/systemmanager/add_group", methods=["POST"])
@login_required
@permission_required("superadmin")
def add_group_inline():
    name = request.form["name"]
    if PermissionGroup.query.filter_by(name=name).first():
        flash("Gruppe existiert bereits!", "danger")
    else:
        g = PermissionGroup(name=name)
        db.session.add(g)
        db.session.commit()
        flash("Gruppe hinzugefügt!", "success")
    service_id = Service.query.filter_by(name="Permission Control").first().id
    return redirect(url_for("service_page", service_id=service_id))

@app.route("/systemmanager/update_group/<int:group_id>", methods=["POST"])
@login_required
@permission_required("superadmin")
def update_group_inline(group_id):
    g = PermissionGroup.query.get_or_404(group_id)
    g.name = request.form["name"]
    db.session.commit()
    flash("Gruppe aktualisiert!", "success")
    service_id = Service.query.filter_by(name="Permission Control").first().id
    return redirect(url_for("service_page", service_id=service_id))

@app.route("/systemmanager/delete_group/<int:group_id>", methods=["POST"])
@login_required
@permission_required("superadmin")
def delete_group_inline(group_id):
    g = PermissionGroup.query.get_or_404(group_id)
    db.session.delete(g)
    db.session.commit()
    flash("Gruppe gelöscht!", "success")
    service_id = Service.query.filter_by(name="Permission Control").first().id
    return redirect(url_for("service_page", service_id=service_id))

# --- Service Page ---
@app.route("/services/<int:service_id>")
@login_required
def service_page(service_id):
    service = Service.query.get_or_404(service_id)

    if service.required_permission and not current_user.has_permission(service.required_permission):
        flash("Du hast keine Berechtigung für diesen Dienst.", "danger")
        return redirect(url_for("dashboard"))

    template_to_render = f"services/{service.template_file}" if service.template_file else "service.html"

    context = {
        "service": service,
        "active_page": f"service_{service.id}"
    }

    # User Control Daten
    if service.name == "User Control":
        context["users"] = User.query.all()
        context["all_groups"] = PermissionGroup.query.all()

    # Permission Control Daten
    if service.name == "Permission Control":
        context["all_groups"] = PermissionGroup.query.all()

    return render_template(template_to_render, **context)

# --- APP STARTUP ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # Superadmin Gruppe
        superadmin_group = PermissionGroup.query.filter_by(name="superadmin").first()
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

        # Home Service
        home_service = Service.query.filter_by(name="Home").first()
        if not home_service:
            home_service = Service(
                name="Home",
                description="Startseite (Home) als Service.",
                required_permission=None,
                template_file="home.html"
            )
            db.session.add(home_service)
            db.session.commit()

        # User Control Service
        user_control = Service.query.filter_by(name="User Control").first()
        if not user_control:
            user_control = Service(
                name="User Control",
                description="Zentraler Verwaltungsdienst für Benutzerverwaltung.",
                required_permission="superadmin",
                template_file="user_control.html"
            )
            db.session.add(user_control)
            db.session.commit()

        # Permission Control Service
        permission_control = Service.query.filter_by(name="Permission Control").first()
        if not permission_control:
            permission_control = Service(
                name="Permission Control",
                description="Verwaltung der Berechtigungsgruppen.",
                required_permission="superadmin",
                template_file="permission_control.html"
            )
            db.session.add(permission_control)
            db.session.commit()

    app.run(debug=True)
