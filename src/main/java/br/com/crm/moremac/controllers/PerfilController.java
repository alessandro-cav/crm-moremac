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
			@RequestParam Integer quantidade, @RequestParam String ordem, @RequestParam String ordenarPor) {
		return ResponseEntity.ok(this.service
				.buscarTodos(PageRequest.of(pagina, quantidade, Sort.by(Direction.valueOf(ordem), ordenarPor))));
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

	@PostMapping("/filtro")
	public ResponseEntity<List<PerfilResponseDTO>> filtroPerfil(
			@RequestBody FiltroPerfilRequestDTO filtroPerfilRequestDTO, @RequestParam Integer pagina,
			@RequestParam Integer quantidade, @RequestParam String ordem, @RequestParam String ordenarPor) {
		return ResponseEntity.ok(this.service.filtroPerfil(filtroPerfilRequestDTO,
				PageRequest.of(pagina, quantidade, Sort.by(Direction.valueOf(ordem), ordenarPor))));
	}
}
