package br.com.crm.moremac.responses;

import java.io.Serializable;

public class UsuarioTokenResponseDTO implements Serializable {

	private static final long serialVersionUID = 1L;

	private UsuarioResponseDTO usuario;

	private String token;

	public UsuarioResponseDTO getUsuario() {
		return usuario;
	}

	public void setUsuario(UsuarioResponseDTO usuario) {
		this.usuario = usuario;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}


}
