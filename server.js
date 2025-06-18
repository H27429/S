const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = 3000;
const SECRET_KEY = 'mysecretkey'; // В реальном проекте храни в .env

// Подключаем SQLite
const db = new sqlite3.Database('./users.db');

// Создаём таблицу, если её нет
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)`);

// Настройки сервера
app.use(cors());
app.use(express.json());

// Регистрация
app.post('/register', (req, res) => {
	const { username, password } = req.body;

	db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
		if (row) {
			return res.status(400).json({ message: 'Пользователь уже существует' });
		}

		const hashedPassword = bcrypt.hashSync(password, 10);

		db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
			if (err) return res.status(500).json({ message: 'Ошибка при регистрации' });
			res.json({ message: 'Пользователь успешно зарегистрирован' });
		});
	});
});

// Авторизация
app.post('/login', (req, res) => {
	const { username, password } = req.body;

	db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
		if (!user) {
			return res.status(400).json({ message: 'Пользователь не найден' });
		}

		const isPasswordValid = bcrypt.compareSync(password, user.password);
		if (!isPasswordValid) {
			return res.status(400).json({ message: 'Неверный пароль' });
		}

		const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
		res.json({ token });
	});
});

// Защищённый маршрут - Профиль
app.get('/profile', (req, res) => {
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];

	if (!token) return res.status(401).json({ message: 'Нет токена' });

	jwt.verify(token, SECRET_KEY, (err, user) => {
		if (err) return res.status(403).json({ message: 'Неверный токен' });

		db.get('SELECT id, username FROM users WHERE id = ?', [user.id], (err, row) => {
			if (err) return res.status(500).json({ message: 'Ошибка получения профиля' });
			res.json({ id: row.id, username: row.username });
		});
	});
});

// Запуск сервера
app.listen(port, () => {
	console.log(`Сервер запущен на http://localhost:${port}`);
});