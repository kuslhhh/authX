import jwt from 'jsonwebtoken';

const userAuth = async (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return res.json({ successs: false, message: 'No token provided' });
    }

    try {

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (decoded.id) {
            req.body.userId = decoded.id;
        } else {
            return res.json({ successs: false, message: 'Not authorized. login again' });
        }

        next();

    } catch (error) {
        res.json({ successs: false, message: error.message });
    }

} 

export default userAuth;