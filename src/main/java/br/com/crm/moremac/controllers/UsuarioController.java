package br.com.crm.moremac.controllers;

import java.util.List;

import javax.validation.Valid;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import br.com.crm.moremac.requests.FiltroPerfilRequestDTO;
import br.com.crm.moremac.requests.LoginRequestDTO;
import br.com.crm.moremac.requests.SenhasRequestDTO;
import br.com.crm.moremac.requests.UsuarioRequestDTO;
import br.com.crm.moremac.responses.MensagemResponseDTO;
import br.com.crm.moremac.responses.PerfilResponseDTO;
import br.com.crm.moremac.responses.UsuarioResponseDTO;
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

	@PostMapping
	public ResponseEntity<UsuarioResponseDTO> save(@RequestBody @Valid UsuarioRequestDTO usuarioRequestDTO) {
		return ResponseEntity.ok(this.service.save(usuarioRequestDTO));
	}

	@GetMapping("/{id}")
	public ResponseEntity<UsuarioResponseDTO> buscarPeloId(@PathVariable(name = "id") Long id) {
		return ResponseEntity.ok(this.service.buscarPeloId(id));
	}

	@GetMapping
	public ResponseEntity<List<UsuarioResponseDTO>> buscarTodos(@RequestParam Integer pagina,
			@RequestParam Integer quantidade, @RequestParam String ordem, @RequestParam String ordenarPor) {
		return ResponseEntity.ok(this.service
				.buscarTodos(PageRequest.of(pagina, quantidade, Sort.by(Direction.valueOf(ordem), ordenarPor))));
	}

	@PutMapping("/{id}")
	public ResponseEntity<UsuarioResponseDTO> atualizar(@PathVariable(name = "id") Long id,
			@Valid @RequestBody UsuarioRequestDTO usuarioRequestDTO) {
		return ResponseEntity.ok(this.service.atualizar(id, usuarioRequestDTO));
	}

	@DeleteMapping("/{id}")
	public ResponseEntity<MensagemResponseDTO> ativarEInativar(@PathVariable(name = "id") Long id) {
		return ResponseEntity.ok(this.service.ativarEInativar(id));
	}
	
	/*
	 * @PostMapping("/filtro") public ResponseEntity<List<UsuarioResponseDTO>>
	 * filtroUsuario(
	 * 
	 * @RequestBody FiltroRequestDTO filtroPerfilRequestDTO, @RequestParam Integer
	 * pagina,
	 * 
	 * @RequestParam Integer quantidade, @RequestParam String ordem, @RequestParam
	 * String ordenarPor) { return
	 * ResponseEntity.ok(this.service.filtroUsuario(filtroPerfilRequestDTO,
	 * PageRequest.of(pagina, quantidade, Sort.by(Direction.valueOf(ordem),
	 * ordenarPor)))); }
	 */

}
