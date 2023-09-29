const bcryptjs = require("bcryptjs");
const AppError = require("../utils/AppError");

class UserCreateServices {
  constructor(userRepository) {
    this.userRepository = userRepository;
  }

  async execute({ name, email, password }) {
    const checkUsersExist = await this.userRepository.findByEmail(email);

    if (checkUsersExist) {
      throw new AppError("E-mail já em uso");
    }

    const hashedPassword = bcryptjs.hashSync(password, 8);

    const userCreated = await this.userRepository.create({
      name,
      email,
      password: hashedPassword,
    });

    return userCreated;
  }
}

module.exports = UserCreateServices;
