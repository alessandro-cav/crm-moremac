package br.com.crm.moremac.controllers;

import javax.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import br.com.crm.moremac.requests.LoginRequestDTO;
import br.com.crm.moremac.requests.SenhasRequestDTO;
import br.com.crm.moremac.responses.MensagemResponseDTO;
import br.com.crm.moremac.services.UsuarioService;

@RestController
@RequestMapping("/usuarios")
public class UsuarioController {

	private final UsuarioService service;

	public UsuarioController(UsuarioService service) {
		this.service = service;
	}

	@PostMapping("/forgot_password")
	public ResponseEntity<Void> esqueciMinhaSenha(@RequestBody @Valid LoginRequestDTO loginRequestDTO) {
		this.service.esqueciMinhaSenha(loginRequestDTO);
		return ResponseEntity.ok().build();
	}

	@PostMapping("/reset_password")
	public ResponseEntity<MensagemResponseDTO> resetarSenha(@RequestParam String token,
			@RequestBody @Valid SenhasRequestDTO senhasRequestDTO) {
		return ResponseEntity.ok(this.service.resetarSenha(token, senhasRequestDTO));
	}

}
