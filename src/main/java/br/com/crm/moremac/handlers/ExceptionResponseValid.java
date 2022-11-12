package br.com.crm.moremac.handlers;

import java.time.LocalDateTime;
import java.util.List;

public class ExceptionResponseValid {

	private String name;

	private List<String> mensagens;

	private LocalDateTime datahora;

	private int valor;

	public ExceptionResponseValid(LocalDateTime now, List<String> mensagens, String name, int value) {
		this.name = name;
		this.mensagens = mensagens;
		this.datahora = now;
		this.valor = value;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public List<String> getMensagens() {
		return mensagens;
	}

	public void setMensagens(List<String> mensagens) {
		this.mensagens = mensagens;
	}

	public LocalDateTime getDatahora() {
		return datahora;
	}

	public void setDatahora(LocalDateTime datahora) {
		this.datahora = datahora;
	}

	public int getValor() {
		return valor;
	}

	public void setValor(int valor) {
		this.valor = valor;
	}
	
	
}
