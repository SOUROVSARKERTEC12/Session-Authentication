import express from 'express';
import dotenv from 'dotenv';
import routes from './routes/index.js';
import sequelize from './config/database.config.js';
import cookieParser from 'cookie-parser';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 5000;

sequelize.sync()
    .then(() => console.log('Database synced'))
    .catch(err => console.log('Error syncing database:', err));
// Start server
(async () => {
    try {
        await sequelize.authenticate();
        console.log('Database connected');
        app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
})();


// Routes
app.use('/api', routes);



