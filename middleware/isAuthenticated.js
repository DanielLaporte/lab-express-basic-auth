const isAuthenticated = (req, res, next) => {
    if (req.session.currentUser) {
      // El usuario está autenticado, permite que continúe.
      next();
    } else {
      // El usuario no está autenticado, redirige a la página de inicio de sesión.
      res.redirect("/auth/login");
    }
  };

  module.exports = isAuthenticated;