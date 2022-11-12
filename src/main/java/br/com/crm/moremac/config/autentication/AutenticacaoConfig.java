package br.com.crm.moremac.config.autentication;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;

import br.com.crm.moremac.responses.AutenticacaoResponseDTO;

@Configuration
public class AutenticacaoConfig {


	public AutenticacaoResponseDTO gerarAutenticacaoDTO(Authentication authentication) {
		if (authentication == null) {
			throw new RuntimeException("autenticação é nula.");
		}
		if (!(authentication.getDetails() instanceof AutenticacaoResponseDTO)) {
			throw new RuntimeException("Falha ao carregar a classe de detalhes de autenticação");
		}
		return (AutenticacaoResponseDTO) authentication.getDetails();
	}
}

