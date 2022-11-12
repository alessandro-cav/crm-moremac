package br.com.crm.moremac.controllers;

import java.util.List;

import javax.validation.Valid;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import br.com.crm.moremac.requests.PerfilRequestDTO;
import br.com.crm.moremac.responses.PerfilResponseDTO;
import br.com.crm.moremac.services.PerfilService;

@RestController
@RequestMapping("/perfis")
public class PerfilController {

	private final PerfilService service;

	public PerfilController(PerfilService service) {
		this.service = service;
	}

	@PostMapping
	public ResponseEntity<PerfilResponseDTO> salvar(@RequestBody @Valid PerfilRequestDTO perfilRequestDTO) {
		return ResponseEntity.ok(this.service.salvar(perfilRequestDTO));
	}

	@GetMapping
	public ResponseEntity<List<PerfilResponseDTO>> buscarTodos(@RequestParam Integer pagina,
			@RequestParam Integer quantidade, @RequestParam String ordem, @RequestParam String ordenarPor,
			@CurrentSecurityContext(expression = "authentication") Authentication authentication) {
		return ResponseEntity.ok(this.service.buscarTodos(authentication,
				PageRequest.of(pagina, quantidade, Sort.by(Direction.valueOf(ordem), ordenarPor))));
	}

	@DeleteMapping("/{id}")
	public ResponseEntity<Void> excluirPeloId(@PathVariable(name = "id") Long id) {
		this.service.excluirPeloId(id);
		return ResponseEntity.noContent().build();
	}

	@GetMapping("/{id}")
	public ResponseEntity<PerfilResponseDTO> buscarPeloId(@PathVariable(name = "id") Long id) {
		return ResponseEntity.ok(this.service.buscarPeloId(id));
	}

	@PutMapping("/{id}")
	public ResponseEntity<PerfilResponseDTO> atualizar(@PathVariable(name = "id") Long id,
			@Valid @RequestBody PerfilRequestDTO perfilRequestDTO) {
		return ResponseEntity.ok(this.service.atualizar(id, perfilRequestDTO));
	}

	@GetMapping("/filtro")
	public ResponseEntity<List<PerfilResponseDTO>> filtrarPerfilPeloNome(
			@CurrentSecurityContext(expression = "authentication") Authentication authentication,
			@RequestParam String nome) {
		return ResponseEntity.ok(this.service.filtrarPerfilPeloNome(authentication, nome));
	}

}
