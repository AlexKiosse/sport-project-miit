package com.sport.project.dao.repository;

import com.sport.project.dao.entity.TeacherEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TeacherRepository extends JpaRepository<TeacherEntity, Integer> {

    Optional<TeacherEntity> findByLogin(String login);

    @Query("SELECT t FROM teacher_entity t WHERE t.moderator = :moderator")
    List<TeacherEntity> findByIsModerator(@Param("moderator") boolean moderator);

    List<TeacherEntity> findByFullNameFirstName(String firstName);

    List<TeacherEntity> findByFullNameLastName(String lastName);

    List<TeacherEntity> findByFullNamePatronymic(String patronymic);

    List<TeacherEntity> findByFullNameFirstNameAndFullNameLastName(
            String firstName, String lastName);

    List<TeacherEntity> findByFullName_FirstNameAndFullName_LastName(String firstName, String lastName);


    List<TeacherEntity> findByFullNameFirstNameAndFullNameLastNameAndFullNamePatronymic(
            String firstName, String lastName, String patronymic);

}


