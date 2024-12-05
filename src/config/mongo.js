import mongoose from 'mongoose';

const connect = async () => {

    mongoose.connection.on('connected', () => console.log('MongoDB connected'))

    await mongoose.connect(process.env.MONGO_URI)
}

export default connect;