var express = require('express');
var router = express.Router();
let userController = require('../controllers/users')
let { RegisterValidator, ChangePasswordValidator, handleResultValidator } = require('../utils/validatorHandler')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let {checkLogin} = require('../utils/authHandler')
let fs = require('fs')
let path = require('path')

// Đọc private key (khóa bí mật) từ file để ký JWT
let privateKey = fs.readFileSync(path.join(__dirname, '../keys/private.key'), 'utf8')

/* POST đăng ký tài khoản */
router.post('/register', RegisterValidator, handleResultValidator, async function (req, res, next) {
    let newUser = userController.CreateAnUser(
        req.body.username,
        req.body.password,
        req.body.email,
        "69aa8360450df994c1ce6c4c"
    );
    await newUser.save()
    res.send({
        message: "dang ki thanh cong"
    })
});

/* POST đăng nhập */
router.post('/login', async function (req, res, next) {
    let { username, password } = req.body;
    let getUser = await userController.FindByUsername(username);
    if (!getUser) {
        res.status(403).send("tai khoan khong ton tai")
    } else {
        if (getUser.lockTime && getUser.lockTime > Date.now()) {
            res.status(403).send("tai khoan dang bi ban");
            return;
        }
        if (bcrypt.compareSync(password, getUser.password)) {
            await userController.SuccessLogin(getUser);
            // Ký token bằng private key với thuật toán RS256
            let token = jwt.sign({
                id: getUser._id
            }, privateKey, {
                algorithm: 'RS256', // Thuật toán bất đối xứng (asymmetric)
                expiresIn: '30d'
            })
            res.send(token)
        } else {
            await userController.FailLogin(getUser);
            res.status(403).send("thong tin dang nhap khong dung")
        }
    }
});

/* GET lấy thông tin user hiện tại (yêu cầu đăng nhập) */
router.get('/me', checkLogin, function(req, res, next){
    res.send(req.user)
})

/* PUT đổi mật khẩu (yêu cầu đăng nhập) */
router.put('/changepassword', checkLogin, ChangePasswordValidator, handleResultValidator, async function(req, res, next) {
    let { oldpassword, newpassword } = req.body;
    let user = req.user; // Lấy user hiện tại từ checkLogin middleware

    // Gọi hàm ChangePassword từ controller để xử lý toàn bộ logic
    let result = await userController.ChangePassword(user, oldpassword, newpassword);

    if (!result.success) {
        // Nếu mật khẩu cũ không đúng, trả về lỗi 400
        return res.status(400).send({ message: result.message });
    }

    // Đổi mật khẩu thành công
    res.send({ message: result.message });
});

module.exports = router;
