package br.com.crm.moremac.handlers;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.validation.ObjectError;

import com.fasterxml.jackson.annotation.JsonFormat;


public class ErrorResponse {

	@JsonFormat(pattern = "dd/MM/yyyy HH:mm:ss")
	private LocalDateTime dataErro;

	private List<String> erros;

	public ErrorResponse(LocalDateTime dataErro, List<ObjectError> allErrors) {
		this.dataErro = dataErro;
		this.erros = allErrors.stream().map(erro -> erro.getDefaultMessage()).sorted().collect(Collectors.toList());
	}

	public LocalDateTime getDataErro() {
		return dataErro;
	}

	public void setDataErro(LocalDateTime dataErro) {
		this.dataErro = dataErro;
	}

	public List<String> getErros() {
		return erros;
	}

	public void setErros(List<String> erros) {
		this.erros = erros;
	}
	
}

