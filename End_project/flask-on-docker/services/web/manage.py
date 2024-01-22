from flask.cli import FlaskGroup

from project import app, db, User, Note


cli = FlaskGroup(app)


@cli.command("create_db")
def create_db():
    db.drop_all()
    db.create_all()
    db.session.commit()


@cli.command("seed_db")
def seed_db():
    """Seeds the database."""
    user = User(name="test", email="socer404@gmail.com", password="be4f16a73882f043c35351aee0be7a1661a1da39fad0a9d82f1deadc484b63af", salt="tZIoscKH", totp_secret="IGRVZCHTEGOC3WB53WECVYMUDRLJQHPO")
    db.session.add(user)
    db.session.commit()


if __name__ == "__main__":
    cli()
