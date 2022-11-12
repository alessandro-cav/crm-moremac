package br.com.crm.moremac.handlers;

import java.time.LocalDateTime;


public class ExceptionResponse {

	private String message;

	private String descrition;

	private LocalDateTime timestamp;

	public ExceptionResponse(String message, String descrition, LocalDateTime timestamp) {
		this.message = message;
		this.descrition = descrition;
		this.timestamp = timestamp;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public String getDescrition() {
		return descrition;
	}

	public void setDescrition(String descrition) {
		this.descrition = descrition;
	}

	public LocalDateTime getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(LocalDateTime timestamp) {
		this.timestamp = timestamp;
	}
	
	
}
