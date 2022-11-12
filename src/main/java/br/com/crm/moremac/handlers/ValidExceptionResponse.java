package br.com.crm.moremac.handlers;

import java.util.List;

public class ValidExceptionResponse extends RuntimeException {

	private static final long serialVersionUID = 1L;
	private List<ErrorResponseValid> mensagens;

	public ValidExceptionResponse(List<ErrorResponseValid> mensagens) {
		this.mensagens = mensagens;
	}

	public List<ErrorResponseValid> getMensagens() {
		return mensagens;
	}

	public void setMensagens(List<ErrorResponseValid> mensagens) {
		this.mensagens = mensagens;
	}

}
