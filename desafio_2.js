const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();
const port = 3000;

let users = [];

// Carrega os usuários do arquivo JSON, se existir
const loadUsers = () => {
    try {
        const data = fs.readFileSync('users.json', 'utf-8');
        users = data ? JSON.parse(data) : [];
    } catch (error) {
        console.error('Erro ao carregar usuários:', error);
    }
};

// Salva os usuários no arquivo JSON
const saveUsers = () => {
    try {
        const jsonData = JSON.stringify(users, null, 2);
        fs.writeFileSync('users.json', jsonData);
    } catch (error) {
        console.error('Erro ao salvar usuários:', error);
    }
};

app.use(bodyParser.json());

// Carrega os usuários ao iniciar o servidor
loadUsers();

// Middleware para autenticação
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ mensagem: 'Não autorizado' });
    }

    jwt.verify(token.replace('Bearer ', ''), 'secreto', (err, user) => {
        if (err) {
            return res.status(403).json({ mensagem: 'Sessão inválida' });
        }
        req.user = user;
        next();
    });
};

// Endpoint cadastro
app.post('/signup', (req, res) => {
    const { nome, email, senha, telefones } = req.body;

    // Verifica e-mail
    if (users.find(user => user.email === email)) {
        return res.status(400).json({ mensagem: 'E-mail já cadastrado' });
    }

    const user = {
        id: Math.random().toString(36).substr(2, 9), // Gerando um ID
        nome,
        email,
        senha,
        telefones,
        data_criacao: new Date(),
        data_atualizacao: new Date(),
        ultimo_login: new Date(),
    };

    // Gerando um token (JWT)
    const token = jwt.sign(user, 'secreto', { expiresIn: '30m' });
    user.token = token;

    users.push(user);

    // Salva os usuários no arquivo JSON
    saveUsers();

    res.json({
        id: user.id,
        data_criacao: user.data_criacao,
        data_atualizacao: user.data_atualizacao,
        ultimo_login: user.ultimo_login,
        token: user.token,
    });
});

// Endpoint autenticação
app.post('/signin', (req, res) => {
    const { email, senha } = req.body;

    const user = users.find(u => u.email === email && u.senha === senha);

    if (!user) {
        return res.status(401).json({ mensagem: 'Usuário e/ou senha inválidos' });
    }

    // Atualizando informacao e gerando novo token 
    user.data_atualizacao = new Date();
    user.ultimo_login = new Date();
    const token = jwt.sign(user, 'secreto', { expiresIn: '30m' });
    user.token = token;

    // Salva os usuários no arquivo JSON
    saveUsers();

    res.json({
        id: user.id,
        data_criacao: user.data_criacao,
        data_atualizacao: user.data_atualizacao,
        ultimo_login: user.ultimo_login,
        token: user.token,
    });
});

// Usuário autenticado
app.get('/me', authenticateToken, (req, res) => {
    res.json(req.user);
});

// Rota não encontrada
app.use((req, res) => {
    res.status(404).json({ mensagem: 'Endpoint não encontrado' });
});

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});
