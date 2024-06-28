package com.example;

import java.sql.SQLException;
import java.util.Map;
import java.util.logging.Level;

import com.example.model.ErrorBean;
import com.example.model.message.MessageDTO;
import com.example.model.message.MessagesDAO;
import com.example.model.user.LoginUserModel;
import com.example.model.user.UserDTO;
import com.example.model.user.UsersDAO;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.mvc.Controller;
import jakarta.mvc.Models;
import jakarta.security.enterprise.identitystore.Pbkdf2PasswordHash;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.BeanParam;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import lombok.NoArgsConstructor;
import lombok.extern.java.Log;

/**
 * Jakarta MVCのコンロトーラクラスです。@Controllerアノテーションを付けましょう。
 * 
 * コントローラクラスはCDI beanであることが必須で、必ず@RequestScopedを付けます。
 * 
 * CDI beanには引数のないコンストラクタが必須なので、
 * Lombokの@NoArgsConstructorで空っぽのコンストラクタを作成します。
 * 
 * @Path はこのクラス全体が扱うURLのパスで、JAX-RSのアノテーションです。
 * これは @ApplicationPath からの相対パスとなります。
 * パスの先頭の/と末尾の/はあってもなくても同じです。
 */
@Controller
@RequestScoped
@NoArgsConstructor(force = true)
@Log
@Path("/")
public class MyController {
	private final Models models;

	private final MessagesDAO messagesDAO;

	private final UsersDAO usersDAO;

	private final LoginUserModel loginUserModel;

	private final ErrorBean errorBean;

	private final Pbkdf2PasswordHash passwordHash;

	private Map<String, String> HASH_PARAMS = Map.of(
			"Pbkdf2PasswordHash.Iterations", "210000",
			"Pbkdf2PasswordHash.Algorithm", "PBKDF2WithHmacSHA512",
			"Pbkdf2PasswordHash.SaltSizeBytes", "32");

	@Inject
	public MyController(Models models, MessagesDAO messagesDAO, UsersDAO usersDAO, LoginUserModel loginUserModel,
			ErrorBean errorBean, Pbkdf2PasswordHash passwordHash,
			HttpServletRequest req) {
		this.models = models;
		this.messagesDAO = messagesDAO;
		this.usersDAO = usersDAO;
		this.loginUserModel = loginUserModel;
		this.errorBean = errorBean;
		this.passwordHash = passwordHash;
		passwordHash.initialize(HASH_PARAMS);

		log.log(Level.INFO, "[ip]%s [url]%s".formatted(
				req.getRemoteAddr(),
				req.getRequestURL().toString()));
	}

	@GET
	public String home() {
		models.put("appName", "メッセージアプリ");
		return "index.jsp";
	}

	@GET
	@Path("list")
	public String getMessage() throws SQLException {
		if (loginUserModel.getName() == null) {
			return "redirect:login";
		}
		models.put("messages", messagesDAO.getAll());
		return "list.jsp";
	}

	@POST
	@Path("list")
	public String postMessage(@BeanParam MessageDTO mes) throws SQLException {
		mes.setName(loginUserModel.getName());
		messagesDAO.create(mes);
		return "redirect:list";
	}

	@GET
	@Path("clear")
	public String clearMessage() throws SQLException {
		messagesDAO.deleteAll();
		return "redirect:list";
	}

	@GET
	@Path("login")
	public String getLogin() {
		loginUserModel.setName(null);
		return "login.jsp";
	}

	@POST
	@Path("login")
	public String postLogin(@BeanParam UserDTO userDTO) throws SQLException {
		UserDTO user = usersDAO.get(userDTO.getName());
		if (user != null && passwordHash.verify(userDTO.getPassword().toCharArray(), user.getPassword())) {
			loginUserModel.setName(userDTO.getName());
			return "redirect:list";
		}
		errorBean.setMessage("ユーザ名またはパスワードが異なります");
		return "redirect:login";
	}

	@GET
	@Path("search")
	public String getSearch(@QueryParam("keyword") String keyword) throws SQLException {
		models.put("messages", messagesDAO.search(keyword));
		return "list.jsp";
	}

	@GET
	@Path("users")
	public String getUsers() throws SQLException {
		models.put("users", usersDAO.getAll());
		return "users.jsp";
	}

	@POST
	@Path("users")
	public String createUsers(@BeanParam UserDTO user) throws SQLException {
		var hash = passwordHash.generate(user.getPassword().toCharArray());
		user.setPassword(hash);
		usersDAO.create(user);
		return "redirect:users";
	}
	
	@POST
	@Path("user_delete")
	public String deleteUser(@FormParam("name") String name) throws SQLException {
		usersDAO.delete(name);
		return "redirect:users";
	}
	
	@POST
	@Path("user_update")
	public String updateUser(@BeanParam UserDTO user) throws SQLException {
		if (!user.getPassword().equals("")) {
			var hash = passwordHash.generate(user.getPassword().toCharArray());
			user.setPassword(hash);
		}
		usersDAO.update(user);
		return "redirect:users";
	}
}
