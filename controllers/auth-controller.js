const { User } = require("../models/user");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const { HttpError, ctrlWrapper } = require("../helpers");

const { SECRET_KEY } = process.env;

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  try {
    const decodedToken = jwt.verify(token, SECRET_KEY);
    const user = await User.findById(decodedToken.id);
    
    if (!user || user.token !== token) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: "Forbidden" });
  }
};

const register = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user) {
    throw HttpError(409, "Email in use");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = await User.create({ ...req.body, password: hashedPassword });

  res.status(201).json({
    email: newUser.email,
    subscription: newUser.subscription,
  });
};

const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    throw HttpError(401, "Email or password is wrong");
  }
  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    throw HttpError(401, "Email or password is wrong");
  }
  const payload = { id: user._id };

  const token = jwt.sign(payload, SECRET_KEY, {
    expiresIn: "23h",
  });
  await User.findByIdAndUpdate(user._id, { token });
  res.status(200).json({
    token,
    user: {
      email: user.email,
      subscription: user.subscription,
    },
  });
};

const getCurrent = async (req, res) => {
  const { email, subscription } = req.user;
  res.json({
    email,
    subscription,
  });
};

const logout = async (req, res) => {
  const { id } = req.user;
  await User.findByIdAndUpdate(id, { token: "" });
  res.status(204).json();
};
const updateSubscription = async (req, res) => {
  const { _id } = req.user;
  console.log(_id);
  const result = await User.findByIdAndUpdate(_id, req.body, { new: true });
  res.json(result);
};

module.exports = {
  register: ctrlWrapper(register),
  login: ctrlWrapper(login),
  getCurrent: [authenticateToken, ctrlWrapper(getCurrent)],
  logout: [authenticateToken, ctrlWrapper(logout)],
  updateSubscription: [authenticateToken, ctrlWrapper(updateSubscription)],
};