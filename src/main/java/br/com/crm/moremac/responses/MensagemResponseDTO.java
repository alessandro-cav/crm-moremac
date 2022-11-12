package br.com.crm.moremac.responses;

import java.io.Serializable;

public class MensagemResponseDTO  implements Serializable {

	private static final long serialVersionUID = 1L;

	private String messagem;

	public MensagemResponseDTO(String mensagem) {
		this.messagem = mensagem;
	}

	public String getMessagem() {
		return messagem;
	}

	public void setMessagem(String messagem) {
		this.messagem = messagem;
	}

	public static MensagemResponseDTO getMenssagem(String mensagem) {
		return new MensagemResponseDTO(mensagem);
	}

}