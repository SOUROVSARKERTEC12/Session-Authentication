import { DataTypes } from 'sequelize';
import sequelize from '../config/database.config.js';


const OTPStore = sequelize.define('OTPStore', {
    otp: {
        type: DataTypes.STRING,
        allowNull: false
    },
    tempUserId: {
        type: DataTypes.INTEGER,
        allowNull: false
    },
    email: {
        type: DataTypes.STRING,
        unique: true,
    },
});

export default OTPStore;
