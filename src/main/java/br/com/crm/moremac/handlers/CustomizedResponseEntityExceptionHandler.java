package br.com.crm.moremac.handlers;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import com.auth0.jwt.exceptions.TokenExpiredException;

@RestController
@RestControllerAdvice
public class CustomizedResponseEntityExceptionHandler {

	@ExceptionHandler(Exception.class)
	public ResponseEntity<Object> allHandlerException(Exception ex, WebRequest request) {
		return new ResponseEntity<Object>(
				new ExceptionResponse(ex.getMessage(), request.getDescription(false), LocalDateTime.now()),
				HttpStatus.INTERNAL_SERVER_ERROR);
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Object> allHandlerMethodArgumentNotValidException(MethodArgumentNotValidException ex,
			WebRequest request) {
		return new ResponseEntity<Object>(new ErrorResponse(LocalDateTime.now(), ex.getBindingResult().getAllErrors()),
				HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(BadRequestException.class)
	public ResponseEntity<Object> allHandlerBadRequestException(BadRequestException ex, WebRequest request) {
		return new ResponseEntity<Object>(
				new ExceptionResponse(ex.getMessage(), request.getDescription(false), LocalDateTime.now()),
				HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(ObjetoNotFoundException.class)
	public ResponseEntity<Object> handlerFuncionarioNotFoundException(ObjetoNotFoundException ex, WebRequest request) {
		return new ResponseEntity<Object>(
				new ExceptionResponse(ex.getMessage(), request.getDescription(false), LocalDateTime.now()),
				HttpStatus.NOT_FOUND);
	}

	@ExceptionHandler(TokenExpiredException.class)
	public ResponseEntity<Object> tokenExpirado(TokenExpiredException ex, WebRequest request) {
		return new ResponseEntity<Object>(
				new ExceptionResponse(ex.getMessage(), request.getDescription(false), LocalDateTime.now()),
				HttpStatus.NON_AUTHORITATIVE_INFORMATION);
	}

	@ExceptionHandler(ValidExceptionResponse.class)
	public final ResponseEntity<Object> handlerValidacao(ValidExceptionResponse ex) {
		List<String> mensagens = new ArrayList<String>();
		ex.getMensagens().forEach(erro -> mensagens.add(erro.getErro()));
		ExceptionResponseValid exceptionResponse = new ExceptionResponseValid(LocalDateTime.now(), mensagens,
				HttpStatus.BAD_REQUEST.name(), HttpStatus.BAD_REQUEST.value());

		return new ResponseEntity<Object>(exceptionResponse, HttpStatus.BAD_REQUEST);
	}
}
