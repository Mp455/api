const bcryptjs = require("bcryptjs");
const AppError = require("../utils/AppError");
const sqliteConnection = require("../database/sqlite");

class UsersController {
  async create(request, response) {
    const { name, email, password } = request.body;

    const database = await sqliteConnection();
    const checkUsersExist = await database.get(
      "SELECT * FROM users WHERE email = (?)",
      [email]
    );

    if (checkUsersExist) {
      throw new AppError("E-mail já em uso");
    }

    const hashedPassword = bcryptjs.hashSync(password, 8);

    await database.run(
      "INSERT INTO users (name, email, password) VALUES (?,?,?)",
      [name, email, hashedPassword]
    );

    return response.status(201).json();
  }

  async update(request, response) {
    const { name, email, password, oldPassword } = request.body;
    const user_id = request.user.id;

    const database = await sqliteConnection();
    const user = await database.get("SELECT * FROM users WHERE id = (?)", [
      user_id,
    ]);

    if (!user) {
      throw new AppError("Usuário não encontrado");
    }

    const userWithUpdateEmail = await database.get(
      "SELECT * FROM users WHERE email = (?)",
      [email]
    );

    if (userWithUpdateEmail && userWithUpdateEmail.id !== user.id) {
      throw new AppError("Este e-mail já está em uso");
    }

    user.name = name ?? user.name;
    user.email = email ?? user.email;

    if (password && !oldPassword) {
      throw new AppError(
        "Você deve informar a senha atual para definir a nova senha"
      );
    }

    if (password && oldPassword) {
      const checkOldPassword = await bcryptjs.compare(
        oldPassword,
        user.password
      );

      if (!checkOldPassword) {
        throw new AppError("Senha antiga não confere");
      }

      user.password = bcryptjs.hashSync(password, 8);
    }

    await database.run(
      `UPDATE users SET name = ?, email = ?, password = ?, updated_at = DATETIME('now') WHERE id = ?`,
      [user.name, user.email, user.password, user_id]
    );

    return response.json(user);
  }
}

module.exports = UsersController;
