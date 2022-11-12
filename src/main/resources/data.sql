
INSERT INTO tbl_perfil (id_perfil,nome, dt_criacao)
  SELECT nextval('sq_perfil') ,'admin',now()
    WHERE NOT EXISTS (SELECT nome FROM tbl_perfil WHERE id_perfil = 1);

    INSERT INTO tbl_usuario (id_usuario, dt_criacao, login, password, id_perfil, status)
 SELECT nextval('sq_usuario'), now(),'root@gmail.com','$2a$12$W4ga0wBDtSMXGY0y41/PAuY8o0E.SGucCpddVRY6gvZhPxA16bpGi', 1, 'ATIVO'
    WHERE NOT EXISTS (SELECT login FROM tbl_usuario WHERE id_usuario = 1); 