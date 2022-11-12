package br.com.crm.moremac.requests;

import java.io.Serializable;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

public class UsuarioRequestDTO implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	private Long id;
	
	@Email
	private String login;

	@NotBlank(message = "{password.not.blank}")
	@NotNull(message = "{password.not.null}")
	private String password;
	
	@NotNull(message = "{perfil.not.null}")
	private Long idPerfil;
	
	private String status;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

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

	public Long getIdPerfil() {
		return idPerfil;
	}

	public void setIdPerfil(Long idPerfil) {
		this.idPerfil = idPerfil;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

}
