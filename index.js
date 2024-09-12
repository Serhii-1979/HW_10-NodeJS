import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json());

const secret = '777';
const tokenExpiration = '1h';
const refreshExpiration = '7d';

let users = [
    { id: 1, username: 'user1', email: 'user1@example.com', password: bcrypt.hashSync('password1', 10), role: 'user' },
    { id: 2, username: 'user2', email: 'user2@example.com', password: bcrypt.hashSync('password2', 10), role: 'admin' },
    { id: 3, username: 'user3', email: 'user3@example.com', password: bcrypt.hashSync('password3', 10), role: 'user'}
];


const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, secret, (err, user) => {
        if (err) {
            console.error('Ошибка проверки токена:', err);
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

const authorizeRole = (role) => (req, res, next) => {
    if(req.user.role !== role) {
        return res.sendStatus(403);
    }
    next();
};

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) return res.status(401).send('Неверное имя пользователя или пароль');

    const match = bcrypt.compareSync(password, user.password);
    if (!match) return res.status(401).send('Неверное имя пользователя или пароль');

    const token = jwt.sign({ id: user.id, role: user.role }, secret, { expiresIn: tokenExpiration });
    res.json({ token });
});

app.post('/update-email', authenticateJWT, (req, res) => {
    const { newEmail } = req.body;
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).send('Пользователь не найден');

    user.email = newEmail;
    res.json({ message: 'Email успешно обновлен', user });
});

app.delete('/delete-account', authenticateJWT, (req, res) => {
    const userId = req.user.id;
    const initialLength = users.length;
    users = users.filter(u => u.id !== userId);

    if (users.length === initialLength) {
        return res.status(404).send('Пользователь не найден');
    }

    res.json({ message: 'Аккаунт успешно удален' });
});

app.post('/update-role', authenticateJWT, authorizeRole('admin'), (req, res) => {
    const { userId, newRole } = req.body;
    const user = users.find(u => u.id === userId);
    if (!user) return res.status(404).send('Пользователь не найден');

    user.role = newRole;
    res.json({ message: 'Роль успешно обновлена', user });
});

app.post('/refresh-token', authenticateJWT, (req, res) => {
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).send('Пользователь не найден');

    const newToken = jwt.sign({ id: user.id, role: user.role }, secret, { expiresIn: refreshExpiration });
    res.json({ token: newToken });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});
