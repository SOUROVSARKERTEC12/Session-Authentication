import { DataTypes } from 'sequelize';
import sequelize from '../config/database.config.js';

const User = sequelize.define('User', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    username: {
        type: DataTypes.STRING,
        allowNull: false
    },
    email: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: false
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    firstName: {
        type: DataTypes.STRING,
        allowNull: false
    },
    lastName: {
        type: DataTypes.STRING,
        allowNull: false
    },
    verified: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
    },
    firstVisit: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
    },
    role: {
        type: DataTypes.STRING,
        defaultValue: 'user',
        allowNull: false
    }
});

export default User;
