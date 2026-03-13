let userModel = require('../schemas/users');
let bcrypt = require('bcrypt');
let mongoose = require('mongoose');

// ===== MOCK DATABASE (BỘ NHỚ RAM) =====
// Mảng dùng để lưu trữ danh sách các tài khoản người dùng đã đăng ký
let mockUsersDB = [
    {
        _id: "660c1dcb89f3a61b2c45dbd1", // Tài khoản mồi
        username: "admin",
        password: "$2b$10$PXr1e8GRc4Rm2asCafv/bOKfJd/9XoDfYzQtz6oTlk.h5r.O166Zm", // "123456"
        email: "admin@example.com",
        fullName: "Admin Test",
        role: "69aa8360450df994c1ce6c4c",
        loginCount: 0,
        lockTime: null,
        isDeleted: false,
        save: async function() { return this; }
    }
];
// ======================================

module.exports = {
    CreateAnUser: function (username, password,
        email, role, fullname, avatar, status, logincount) {
        
        // Băm mật khẩu luôn tại đây cho chức năng Register
        let hashedPassword = bcrypt.hashSync(password, 10);
        
        // Tạo một object người dùng mới
        let newUser = {
            _id: new mongoose.Types.ObjectId().toString(), // Tạo ra một ID random hợp lệ
            username: username,
            password: hashedPassword,
            email: email,
            fullName: fullname || "",
            avatarUrl: avatar || "",
            status: status || true,
            role: role,
            loginCount: logincount || 0,
            lockTime: null,
            isDeleted: false,
            // Giả lập hàm save() của Mongoose Model
            save: async function() { 
                mockUsersDB.push(this); // Thêm user mới vào Database ảo
                return this; 
            }
        };
        return newUser;
    },
    FindByUsername: async function (username) {
        // Tìm User trong mảng mockUsersDB theo username
        let user = mockUsersDB.find(u => u.username === username && u.isDeleted === false);
        return user || null;
    },
    FailLogin: async function (user) {
        user.loginCount++;
        if (user.loginCount == 3) {
            user.loginCount = 0;
            user.lockTime = new Date(Date.now() + 60 * 60 * 1000)
        }
        await user.save(); // Thực chất không cần làm gì với DB array
    },
    SuccessLogin: async function (user) {
        user.loginCount = 0;
        await user.save();
    },
    GetAllUser: async function () {
        return mockUsersDB.filter(u => u.isDeleted === false);
    },
    FindById: async function (id) {
        let user = mockUsersDB.find(u => u._id === id && u.isDeleted === false);
        return user || null;
    },
    // Đổi mật khẩu: kiểm tra mật khẩu cũ, băm mật khẩu mới và lưu lại
    ChangePassword: async function (user, oldpassword, newpassword) {
        // Kiểm tra xem mật khẩu cũ có khớp với mật khẩu đang lưu không
        let isMatch = bcrypt.compareSync(oldpassword, user.password);
        if (!isMatch) {
            // Trả về lỗi nếu mật khẩu cũ không đúng
            return { success: false, message: "Mat khau cu khong dung" };
        }

        // Băm (hash) mật khẩu mới trước khi lưu vào database
        user.password = bcrypt.hashSync(newpassword, 10);
        await user.save();

        return { success: true, message: "Doi mat khau thanh cong" };
    }
}