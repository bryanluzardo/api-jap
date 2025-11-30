import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"

export async function hashPass (pass) {
    const sal = 15;
    const hashed = bcrypt.hash(pass, sal).then((hash) => {
        return hash
    }) 
    return hashed
}

export async function comparePass (pass, hash) {
    return bcrypt.compare(pass, hash).then((res) => {
        return res
    })
}


export function generarToken(user) {
  const secret = process.env.JWT_SECRET || "dev_secret_change_me";
  const payload = {
    id: user.id,
  };
  return jwt.sign(payload, secret, { expiresIn: "3d" });
} 

export function validarToken(){
    console.log("validar token")
}

export function jwtAuth(req, res, next) {
    const secret = process.env.JWT_SECRET || "dev_secret_change_me";
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
        return res.status(401).json({message: "falta token"});
    }
    try {
        const decoded = jwt.verify(token, secret);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: "token inválido"});
    }

}
