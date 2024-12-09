import { DataTypes } from 'sequelize';
import sequelize from '../config/database.config.js';

const TempUser = sequelize.define('TempUser', {
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
        defaultValue: false
    },
    twoFASecret: {
        type: DataTypes.STRING, // Store 2FA secret
        allowNull: true,
    },
    isTwoFAEnabled: {
        type: DataTypes.BOOLEAN, // Track if 2FA is enabled
        defaultValue: false,
    },
    firstVisit: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    }
});

export default TempUser;
