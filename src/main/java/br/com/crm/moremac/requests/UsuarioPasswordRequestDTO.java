package br.com.crm.moremac.requests;

import java.io.Serializable;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

public class UsuarioPasswordRequestDTO implements Serializable {

	private static final long serialVersionUID = 1L;

	@Email
	@NotNull(message = "{login.not.null}")
	private String login;

	@NotBlank(message = "{password.not.blank}")
	@NotNull(message = "{password.not.null}")
	private String password;

	public String getLogin() {
		return login;
	}

	public void setLogin(String login) {
		this.login = login;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

}
