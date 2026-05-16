package com.sport.project.service;

import com.sport.project.dto.StudentDTO;
import com.sport.project.exception.EntityNotFoundException;

import java.util.List;

/**
 * Сервис для работы со студентами.
 * Предоставляет методы для получения данных о студентах.
 */
public interface StudentService {

    /**
     * Получение студента по идентификатору.
     *
     * @param id идентификатор студента
     * @return данные студента
     * @throws EntityNotFoundException если студент не найден
     */
    StudentDTO findById(Integer id) throws EntityNotFoundException;

    /**
     * Получение студента по логину.
     *
     * @param login логин студента
     * @return данные студента
     * @throws EntityNotFoundException если студент не найден
     */
    StudentDTO findByLogin(String login) throws EntityNotFoundException;

    /**
     * Получение студентов по ФИО.
     *
     * @param firstName имя
     * @param lastName фамилия
     * @param patronymic отчество
     * @return данные студента
     * @throws EntityNotFoundException если студент не найден
     */
    List<StudentDTO> findByFullName(String firstName, String lastName, String patronymic) throws EntityNotFoundException;


    /**
     * Получение студентов по фамилии и имени
     * @param firstName имя
     * @param lastName фамилия
     * @return данные студента
     * @throws EntityNotFoundException если студент не найден
     */
    List<StudentDTO> findByFirstNameAndLastName(String firstName, String lastName);

    /**
     * Получение всех студентов.
     *
     * @return список всех студентов
     */
    List<StudentDTO> findAll();

    /**
     * Получение всех студентов группы.
     *
     * @param groupId идентификатор группы
     * @return список студентов группы
     */
    List<StudentDTO> findByGroup(Integer groupId);

    /**
     * Получение всех студентов секции.
     *
     * @param sectionId идентификатор секции
     * @return список студентов секции
     */
    List<StudentDTO> findBySection(Integer sectionId);

    /**
     * Получение всех студентов медицинской группы.
     *
     * @param healthGroupId идентификатор медицинской группы
     * @return список студентов медицинской группы
     */
    List<StudentDTO> findByHealthGroup(Integer healthGroupId);

    /**
     * Проверка существования студента по логину.
     *
     * @param login логин студента
     * @return true если студент существует, иначе false
     */
    boolean existsByLogin(String login);
}
