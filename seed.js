require('dotenv').config();
const mongoose = require('mongoose');
const { User, OU, Division, Credential } = require('./models');
const bcrypt = require('bcryptjs');

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('MongoDB connected');
    seedData();
  })
  .catch(err => console.log(err));

async function seedData() {
  try {
    // Clear existing data
    await User.deleteMany({});
    await OU.deleteMany({});
    await Division.deleteMany({});
    await Credential.deleteMany({});

    // Create OUs
    const newsManagement = new OU({ name: 'News Management' });
    const softwareReviews = new OU({ name: 'Software Reviews' });
    const hardwareReviews = new OU({ name: 'Hardware Reviews' });
    const opinionPublishing = new OU({ name: 'Opinion Publishing' });

    await newsManagement.save();
    await softwareReviews.save();
    await hardwareReviews.save();
    await opinionPublishing.save();

    // Create Divisions
    const division1 = new Division({ name: 'Finance', ou: newsManagement._id });
    const division2 = new Division({ name: 'IT', ou: softwareReviews._id });
    const division3 = new Division({ name: 'Writing', ou: hardwareReviews._id });
    const division4 = new Division({ name: 'Development', ou: opinionPublishing._id });

    await division1.save();
    await division2.save();
    await division3.save();
    await division4.save();

    // Create Credentials
    const credential1 = new Credential({ system: 'System1', login: 'login1', password: 'password1', division: division1._id });
    const credential2 = new Credential({ system: 'System2', login: 'login2', password: 'password2', division: division2._id });
    const credential3 = new Credential({ system: 'System3', login: 'login3', password: 'password3', division: division3._id });
    const credential4 = new Credential({ system: 'System4', login: 'login4', password: 'password4', division: division4._id });

    await credential1.save();
    await credential2.save();
    await credential3.save();
    await credential4.save();

    // Create Users
    const hashedPassword1 = await bcrypt.hash('password1', 10);
    const hashedPassword2 = await bcrypt.hash('password2', 10);
    const hashedPassword3 = await bcrypt.hash('password3', 10);
    const hashedPassword4 = await bcrypt.hash('password4', 10);
    
    const user1 = new User({ username: 'user1', password: hashedPassword1, role: 'Admin', division: division1._id });
    const user2 = new User({ username: 'user2', password: hashedPassword2, role: 'Normal', division: division2._id });
    const user3 = new User({ username: 'user3', password: hashedPassword3, role: 'Admin', division: division3._id });
    const user4 = new User({ username: 'user4', password: hashedPassword4, role: 'Normal', division: division4._id });

    await user1.save();
    await user2.save();
    await user3.save();
    await user4.save();

    // Link divisions to OUs
    newsManagement.divisions.push(division1._id);
    softwareReviews.divisions.push(division2._id);
    hardwareReviews.divisions.push(division3._id);
    opinionPublishing.divisions.push(division4._id);

    await newsManagement.save();
    await softwareReviews.save();
    await hardwareReviews.save();
    await opinionPublishing.save();

    console.log('Sample data inserted successfully');
    mongoose.disconnect();
  } catch (err) {
    console.error(err);
    mongoose.disconnect();
  }
}
