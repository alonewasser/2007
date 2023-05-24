from flask import Flask, jsonify, request, render_template, redirect, flash, url_for, session
from flask_sqlalchemy import SQLAlchemy
import hashlib
import string
import random
from datetime import datetime
import os

app = Flask(__name__)
app.template_folder = 'C:\\Users\\AloneWasser\\Desktop\\21\\templates'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

registered_users = {}  # Словарь для хранения зарегистрированных пользователей

@app.before_request
def setup():
    # Создание всех таблиц в базе данных
    db.create_all()

    # Вызов функции для создания администратора по умолчанию
    create_default_admin()


# Rest of your code...
# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))
    token = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=False)
    avatars = db.relationship('Avatar', backref='user', lazy=True)

    def __init__(self, username, password, token='', is_admin=False):
        self.username = username
        self.password = password
        self.token = token
        self.is_admin = is_admin

# Модель Аватара
class Avatar(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image_url = db.Column(db.String(200))

    def __init__(self, user_id, image_url):
        self.user_id = user_id
        self.image_url = image_url

# Модель курса
class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), unique=True)
    description = db.Column(db.String(200))

    def __init__(self, title, description):
        self.title = title
        self.description = description

# Rest of your code...

class Question(db.Model):
    __tablename__ = 'question'
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    question = db.Column(db.String(200))
    options = db.relationship('Option', backref='question', cascade='all, delete-orphan')

    def __init__(self, test_id, question):
        self.test_id = test_id
        self.question = question


class Option(db.Model):
    __tablename__ = 'option'
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'))
    option = db.Column(db.String(100))

    def __init__(self, question_id, option):
        self.question_id = question_id
        self.option = option


class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    questions = db.relationship('Question', backref='test', cascade='all, delete-orphan')

    def __init__(self, title, questions):
        self.title = title
        self.questions = questions









def check_admin_status(token):
    user = User.query.filter_by(token=token).first()
    if user and user.is_admin:
        return True
    return False

# ...

# Функция для создания администратора по умолчанию
def create_default_admin():
    default_admin_username = 'admin'
    default_admin_password = 'adminpassword'

    admin = User.query.filter_by(username=default_admin_username, is_admin=True).first()
    if admin is None:
        hashed_password = hash_password(default_admin_password)
        admin = User(username=default_admin_username, password=hashed_password, is_admin=True)
        db.session.add(admin)
        db.session.commit()

# Вспомогательная функция для хеширования пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Вспомогательная функция для проверки пароля
def check_password(password, hashed_password):
    return hashlib.sha256(password.encode()).hexdigest() == hashed_password




def generate_token(token_type):
    if token_type == 'admin':
        admin_token = 'admin_token'  # Админский токен
        hashed_token = hashlib.sha256(admin_token.encode('utf-8')).hexdigest()  # Хеширование админского токена
    else:
        user_token = 'user_token'  # Пользовательский токен
        hashed_token = hashlib.sha256(user_token.encode('utf-8')).hexdigest()  # Хеширование пользовательского токена

    return hashed_token


@app.before_request
def setup():

    # Вызов функции для создания администратора по умолчанию
    create_default_admin()



@app.route('/')
def home():
    token = session.get('token')  # Получение токена из сеанса пользователя
    return render_template('index.html', token=token)
    print("Flask app error:", e)


# Роут для страницы с информацией о конкретном курсе
@app.route('/courses/<int:course_id>')
def course_details(course_id):
    token = request.headers.get('Authorization')
    session['token'] = token  # Сохранение токена в сеансе
    course = Course.query.get(course_id)
    if not course:
        return jsonify({'error': 'Course not found'}), 404

    tests = Test.query.filter_by(course_id=course_id).all()
    return render_template('course_details.html', course=course, tests=tests,
                           token=request.headers.get('Authorization'))




# Роут для страницы с созданием курса
@app.route('/create_course', methods=['POST', 'GET'])
def create_course():
    token = session.get('token')
    username = session.get('username')

    if not token:
        return redirect('/login')

    is_admin_token = (token == generate_token('admin'))  # Проверяем, является ли токен админским

    if not is_admin_token:
        return redirect('/courses')  # Redirect regular users to the "Courses" page

    courses = Course.query.all()

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')

        if not title or not description:
            return jsonify({'error': 'Missing data'}), 400

        course = Course(title=title, description=description)
        db.session.add(course)
        db.session.commit()

        return redirect('/courses')

    return render_template('create_course.html')



@app.route('/courses/<int:add_test_id>/add_test', methods=['GET', 'POST'])
def add_test(add_test_id):
    token = session.get('token')
    username = session.get('username')

    if not token:
        return redirect('/login')

    is_admin_token = (token == generate_token('admin'))

    if not is_admin_token:
        return jsonify({'error': 'Unauthorized'}), 401

    if request.method == 'POST':
        title = request.form.get('title')
        questions = []
        options = []
        correct_answers = []

        for key, value in request.form.items():
            if key.startswith('question-'):
                questions.append(value)
            elif key.startswith('option'):
                options.append(value)
            elif key.startswith('correct_option'):
                correct_answers.append(value)

        if not title or not questions or not options or not correct_answers:
            return jsonify({'error': 'Missing data'}), 400

        test = Test(title=title, questions=questions)
        db.session.add(test)
        db.session.commit()

        for i, question_text in enumerate(questions):
            question = Question(test_id=test.id, question=question_text)
            db.session.add(question)

            for j, option_text in enumerate(options[i * 4: (i + 1) * 4]):
                option = Option(question_id=question.id, option=option_text)
                db.session.add(option)

        db.session.commit()

        return redirect('/courses')

    return render_template('add_questions.html', add_test_id=add_test_id)



@app.route('/add_questions', methods=['GET', 'POST'])
def add_questions():
    if request.method == 'POST':
        # Получите идентификатор теста, который вы хотите добавить
        add_test_id = ...

        return redirect(url_for('add_test', add_test_id=add_test_id))

    # Установите значение add_test_id для отображения в шаблоне при GET-запросе
    add_test_id = ...

    return render_template('add_questions.html', add_test_id=add_test_id)






@app.route('/courses/<int:course_id>/delete', methods=['POST'])
def delete_course(course_id):
    token = session.get('token')
    username = session.get('username')

    if not token:
        return redirect('/login')

    is_admin_token = (token == generate_token('admin'))  # Проверяем, является ли токен админским

    if not is_admin_token:
        return jsonify({'error': 'Unauthorized'}), 401

    course = Course.query.get(course_id)
    if not course:
        return jsonify({'error': 'Course not found'}), 404

    db.session.delete(course)
    db.session.commit()

    return redirect('/courses')



# ...
# Определение функции secure_filename
def secure_filename(filename):
    # Допустимые символы для имени файла
    allowed_chars = string.ascii_letters + string.digits + '._-'

    # Удаляем символы, отличные от допустимых
    cleaned_filename = ''.join(c for c in filename if c in allowed_chars)

    # Генерируем случайное имя файла, если после очистки имя стало пустым
    if not cleaned_filename:
        random_chars = ''.join(random.choices(allowed_chars, k=8))
        cleaned_filename = f'unnamed_{random_chars}'

    return cleaned_filename

# ...
# Функция проверки допустимых расширений файлов
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
#
# @app.route('/upload_avatar', methods=['POST'])
# def upload_avatar():
#     if 'avatar' not in request.files:
#         return 'No file uploaded', 400
#
#     avatar = request.files['avatar']
#
#     if avatar.filename == '':
#         return 'No selected file', 400
#
#     if avatar and allowed_file(avatar.filename):
#         filename = secure_filename(avatar.filename)  # Используем безопасное имя файла
#         avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))  # Сохранение файла аватара
#     else:
#         filename = 'default_avatar.png'  # Используйте дефолтный аватар, если файл не был загружен



# ...
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        # Проверка наличия активной сессии пользователя
        if 'username' in session:
            return redirect(url_for('courses'))

        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')


        user = User.query.filter_by(username=username).first()

        if user:
            error_message = 'Имя пользователя уже существует'
            return render_template('register.html', error_message=error_message)

        if password != confirm_password:
            error_message = 'Пароли не совпадают'
            return render_template('register.html', error_message=error_message)

        # Создание нового пользователя
        token = generate_token()
        new_user = User(username=username, password=hash_password(password), token=token)
        db.session.add(new_user)
        db.session.commit()

        # Успешная регистрация
        flash('Регистрация прошла успешно', 'success')
        return redirect(url_for('courses'))

    return render_template('register.html')




# ...

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        if 'username' in session:
            return redirect(url_for('courses'))

        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if not user or not check_password(password, user.password):
            error_message = 'Неверное имя пользователя или пароль'
            return render_template('login.html', error_message=error_message)

        if user.is_admin:
            token_type = 'admin'
        else:
            token_type = 'user'

        token = generate_token(token_type)

        session['username'] = username
        session['token'] = token
        print(f"Token saved in session: {session['token']}")
        if token_type == 'admin':
            print("Admin token is set")  # Проверка задания админского токена

        flash('Вход выполнен успешно', 'success')
        return redirect(url_for('courses'))

    return render_template('login.html')




# ...

@app.route('/courses')
def courses():
    token = session.get('token')
    username = session.get('username')

    if not token:
        return redirect('/login')

    is_admin_token = (token == generate_token('admin'))  # Проверяем, является ли токен админским

    courses = Course.query.all()

    return render_template('courses.html', courses=courses, username=username, is_admin_token=is_admin_token)









# ...

@app.route('/logout', methods=['POST'])
def logout():
    # Проверка наличия активной сессии пользователя
    if 'username' in session:
        session.pop('username')
        session.pop('token', None)  # Удаление токена из сеанса

    return render_template('login.html')


# ...


# ...

if __name__ == '__main__':
    app.secret_key = 'your_secret_key_here'
    app.run(debug=True)

