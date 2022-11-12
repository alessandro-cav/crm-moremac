package br.com.crm.moremac.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import br.com.crm.moremac.entities.Usuario;

public interface UsuarioRepository  extends JpaRepository<Usuario, Long>{

	Optional<Usuario> findByLogin(String login);

}
