package br.com.crm.moremac.repositories;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

import br.com.crm.moremac.entities.Perfil;

public interface PerfilRepository extends PagingAndSortingRepository<Perfil, Long>, JpaRepository<Perfil, Long> {

	Optional<Perfil> findByNome(String nome);

	@Query("SELECT perfil FROM Perfil perfil WHERE perfil.nome LIKE %:nome%")
	List<Perfil> findByNomeLike(@Param("nome") String nome);

	List<Perfil> findByCnpj(String cnpj, PageRequest pageRequest);

	@Query("SELECT perfil FROM Perfil perfil WHERE perfil.cnpj = :cnpj and perfil.nome LIKE %:nome%")
	List<Perfil> findByCnpjAndNomeLike(@Param("cnpj") String cnpj, @Param("nome") String nome);
}
