import { DataTypes } from 'sequelize';
import sequelize from '../config/database.config.js';

const Session = sequelize.define('Session', {
    id: {
        type: DataTypes.STRING(100),
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    userId: {
        type: DataTypes.STRING(100),
        allowNull: false
    },
    token: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    expiresAt: {
        type: DataTypes.DATE,
        allowNull: false,
    },
});

export default Session;
