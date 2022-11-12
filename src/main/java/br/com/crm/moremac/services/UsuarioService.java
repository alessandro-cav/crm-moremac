package br.com.crm.moremac.services;

import java.util.Date;
import java.util.Optional;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;

import br.com.crm.moremac.config.email.EnviaEmail;
import br.com.crm.moremac.config.jwt.JWTConstants;
import br.com.crm.moremac.entities.Usuario;
import br.com.crm.moremac.handlers.BadRequestException;
import br.com.crm.moremac.handlers.ObjetoNotFoundException;
import br.com.crm.moremac.repositories.UsuarioRepository;
import br.com.crm.moremac.requests.LoginRequestDTO;
import br.com.crm.moremac.requests.SenhasRequestDTO;
import br.com.crm.moremac.responses.MensagemResponseDTO;

@Service
public class UsuarioService implements UserDetailsService {

	private final UsuarioRepository repository;

	private final PasswordEncoder passwordEncod;

	private final EnviaEmail email;

	public UsuarioService(UsuarioRepository repository, PasswordEncoder passwordEncod, EnviaEmail email) {
		this.repository = repository;
		this.passwordEncod = passwordEncod;
		this.email = email;
	}

	public Usuario buscarUsuarioPeloLogin(String username) {
		return this.repository.findByLogin(username)
				.orElseThrow(() -> new ObjetoNotFoundException("Usuário não encontrado."));
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return this.repository.findByLogin(username).map(usuario -> {
			return User.builder().username(usuario.getLogin()).password(usuario.getPassword()).roles(new String[] {})
					.build();
		}).orElseThrow(() -> new BadRequestException("Login invalido."));
	}

	public void esqueciMinhaSenha(LoginRequestDTO loginRequestDTO) {
		this.repository.findByLogin(loginRequestDTO.getLogin()).ifPresentOrElse(usuario -> {

			String token = JWT.create().withSubject(usuario.getLogin())
					.withExpiresAt(new Date(System.currentTimeMillis() + JWTConstants.TOKEN_EXPIRADO_ESQUECI_SENHA))
					.sign(Algorithm.HMAC512(JWTConstants.CHAVE_ASSINATURA));

			String link = JWTConstants.LINK_TOKEN_RESETAR_SENHA + token;

			// String nome = null; // rever isso aqui //nome =
			// this.repository.buscarNomeDoFuncionarioPeloIdUsuario(usuario.getId());

			email.enviarEmail(usuario.getLogin(), usuario.getLogin(), link);
		}, () -> {
			throw new BadRequestException("Login invalído.");
		});
	}

	public MensagemResponseDTO resetarSenha(String token, SenhasRequestDTO senhasRequestDTO) {

		try {
			JWT.require(Algorithm.HMAC512(JWTConstants.CHAVE_ASSINATURA)).build().verify(token).getExpiresAt();

			if (!senhasRequestDTO.getSenha01().equals(senhasRequestDTO.getSenha02())) {
				throw new BadRequestException("Senhas diferentes");
			}

			String login = JWT.decode(token).getSubject();
			Optional<Usuario> usuario = this.repository.findByLogin(login);

			String novaSenhaCodificada = passwordEncod.encode(senhasRequestDTO.getSenha01().trim());
			usuario.get().setPassword(novaSenhaCodificada);
			this.repository.saveAndFlush(usuario.get());

			String mensagem = "Senha alterada com sucesso.";
			return MensagemResponseDTO.getMenssagem(mensagem);

		} catch (TokenExpiredException e) {
			throw new TokenExpiredException("Token expirado: " + e.getMessage());
		}
	}

}
