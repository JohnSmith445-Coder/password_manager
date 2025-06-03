from app import app, db, User

with app.app_context():
    user = User.query.filter_by(username='admin').first()
    if user:
        user.set_password('admin')
        db.session.commit()
        print('Admin password reset to "admin"')
    else:
        print('Admin user not found')