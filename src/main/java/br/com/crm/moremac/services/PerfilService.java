package br.com.crm.moremac.services;

import java.util.List;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import br.com.crm.moremac.entities.Perfil;
import br.com.crm.moremac.handlers.BadRequestException;
import br.com.crm.moremac.handlers.ObjetoNotFoundException;
import br.com.crm.moremac.repositories.PerfilRepository;
import br.com.crm.moremac.requests.PerfilRequestDTO;
import br.com.crm.moremac.responses.PerfilResponseDTO;

@Service
public class PerfilService {

	private final PerfilRepository repository;

	private final ModelMapper modelMapper;

	public PerfilService(PerfilRepository repository, ModelMapper modelMapper) {
		this.repository = repository;
		this.modelMapper = modelMapper;
	}

	public PerfilResponseDTO salvar(PerfilRequestDTO perfilRequestDTO) {
		this.repository.findByNome(perfilRequestDTO.getNome()).ifPresent(perfil -> {
			throw new BadRequestException("Perfil já cadastrado.");
		});

		Perfil perfil = this.modelMapper.map(perfilRequestDTO, Perfil.class);
		perfil = this.repository.save(perfil);
		return this.modelMapper.map(perfil, PerfilResponseDTO.class);
	}

	public List<PerfilResponseDTO> buscarTodos(PageRequest pageRequest) {
		List<PerfilResponseDTO> perfilResponseDTOs = this.repository.findAll(pageRequest).stream().map(perfil -> {
			return this.modelMapper.map(perfil, PerfilResponseDTO.class);
		}).collect(Collectors.toList());
		return perfilResponseDTOs;
	}

	public void excluirPeloId(Long id) {
		this.repository.findById(id).ifPresentOrElse(perfil -> {
			try {

				this.repository.delete(perfil);
			} catch (DataIntegrityViolationException e) {
				throw new BadRequestException("Perfil vinculado ao usuario");
			}
		}, () -> {
			throw new ObjetoNotFoundException("Perfil não encontrado.");
		});
	}

	public PerfilResponseDTO buscarPeloId(Long id) {
		return this.repository.findById(id).map(perfil -> {
			return modelMapper.map(perfil, PerfilResponseDTO.class);
		}).orElseThrow(() -> new ObjetoNotFoundException("Perfil não encontrado."));
	}

	public PerfilResponseDTO atualizar(Long id, PerfilRequestDTO perfilRequestDTO) {
		return this.repository.findById(id).map(perfil -> {
			if (!perfil.getNome().equals(perfilRequestDTO.getNome())) {
				this.repository.findByNome(perfilRequestDTO.getNome()).ifPresent(p -> {
					throw new BadRequestException("Perfil já cadastrado.");
				});
				perfilRequestDTO.setId(perfil.getId());
				perfil = this.modelMapper.map(perfilRequestDTO, Perfil.class);
				perfil = this.repository.save(perfil);
			}
			return this.modelMapper.map(perfil, PerfilResponseDTO.class);
		}).orElseThrow(() -> new ObjetoNotFoundException("Perfil não encontrado."));
	}

	public Perfil buscarPerfilPeloId(Long id) {
		return this.repository.findById(id).orElseThrow(() -> new ObjetoNotFoundException("Perfil não encontrado."));
	}
}