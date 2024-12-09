import { DataTypes } from 'sequelize';
import sequelize from '../config/database.config.js';

const RememberedDevice = sequelize.define('RememberedDevice', {
    userId: {
        type: DataTypes.INTEGER,
        allowNull: false,
    },
    deviceId: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    expirationTime: {
        type: DataTypes.DATE,
        allowNull: false,
    },
});

export default RememberedDevice;
