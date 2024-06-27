const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// User Schema
const userSchema = new Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['Admin', 'Normal', 'Manager'], default: 'Normal' },
  division: { type: Schema.Types.ObjectId, ref: 'Division' }
});


// OU Schema
const ouSchema = new Schema({
  name: { type: String, required: true },
  divisions: [{ type: Schema.Types.ObjectId, ref: 'Division' }]
});


// Division Schema
const divisionSchema = new Schema({
  name: { type: String, required: true },
  ou: { type: Schema.Types.ObjectId, ref: 'OU' },
  credentials: [{ type: Schema.Types.ObjectId, ref: 'Credential' }]
});

// Credential Schema
const credentialSchema = new Schema({
  system: { type: String, required: true },
  login: { type: String, required: true },
  password: { type: String, required: true },
  division: { type: Schema.Types.ObjectId, ref: 'Division' }
});

// Create Models
const User = mongoose.model('User', userSchema);
const OU = mongoose.model('OU', ouSchema);
const Division = mongoose.model('Division', divisionSchema);
const Credential = mongoose.model('Credential', credentialSchema);

// Export Models
module.exports = { User, OU, Division, Credential };
