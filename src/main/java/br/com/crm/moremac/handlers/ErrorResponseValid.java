package br.com.crm.moremac.handlers;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonFormat;

public class ErrorResponseValid {

	@JsonFormat(pattern = "dd/MM/yyyy HH:mm:ss")
	private LocalDateTime dataErro;

	private String erro;

	public ErrorResponseValid(LocalDateTime dataErro, String erro) {
		this.dataErro = dataErro;
		this.erro = erro;
	}

	public LocalDateTime getDataErro() {
		return dataErro;
	}

	public void setDataErro(LocalDateTime dataErro) {
		this.dataErro = dataErro;
	}

	public String getErro() {
		return erro;
	}

	public void setErro(String erro) {
		this.erro = erro;
	}

}
