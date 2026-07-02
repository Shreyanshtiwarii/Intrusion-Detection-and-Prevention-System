"""Registers every route blueprint with the Flask app."""


def register_blueprints(app):
    from routes.auth_routes import auth_bp
    from routes.dashboard_routes import dashboard_bp
    from routes.packet_routes import packet_bp
    from routes.alert_routes import alert_bp
    from routes.ips_routes import ips_bp
    from routes.log_routes import log_bp
    from routes.fim_routes import fim_bp
    from routes.report_routes import report_bp
    from routes.settings_routes import settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(packet_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(ips_bp)
    app.register_blueprint(log_bp)
    app.register_blueprint(fim_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(settings_bp)
