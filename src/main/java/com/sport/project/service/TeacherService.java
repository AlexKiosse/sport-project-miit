package com.sport.project.service;

import com.sport.project.dto.TeacherDTO;
import com.sport.project.exception.EntityNotFoundException;

import java.time.LocalDate;
import java.util.List;

/**
 * Сервис для работы с преподавателями.
 * Предоставляет методы для получения данных о преподавателях.
 */
public interface TeacherService {

    /**
     * Получение преподавателя по идентификатору.
     *
     * @param id идентификатор преподавателя
     * @return данные преподавателя
     * @throws EntityNotFoundException если преподаватель не найден
     */
    TeacherDTO findById(Integer id) throws EntityNotFoundException;

    /**
     * Получение преподавателя по логину.
     *
     * @param login логин преподавателя
     * @return данные преподавателя
     * @throws EntityNotFoundException если преподаватель не найден
     */
    TeacherDTO findByLogin(String login) throws EntityNotFoundException;

    /**
     * Получение преподавателей по ФИО.
     *
     * @param firstName имя
     * @param lastName фамилия
     * @param patronymic отчество
     * @return данные преподавателя
     * @throws EntityNotFoundException если преподаватель не найден
     */
    List<TeacherDTO> findByFullName(String firstName, String lastName, String patronymic) throws EntityNotFoundException;

    /**
     * Получение преподавателей по имени и фамилии для упрощённого поиска
     * @param firstName Имя
     * @param lastName Фамилия
     * @return данные преподавателя
     * @throws EntityNotFoundException если преподаватель не найден
     * */
    List<TeacherDTO> findByFirstNameAndLastName(String firstName, String lastName) throws EntityNotFoundException;

    /**
     * Получение всех преподавателей.
     *
     * @return список всех преподавателей
     */
    List<TeacherDTO> findAll();

    /**
     * Получение всех преподавателей-модераторов.
     *
     * @return список преподавателей со статусом модератора
     */
    List<TeacherDTO> findAllModerators();

    /**
     * Получение преподавателей, проводящих занятия на указанную дату.
     *
     * @param date дата занятий
     * @return список преподавателей
     */
    List<TeacherDTO> findByLessonsDate(LocalDate date);

    /**
     * Проверка существования преподавателя по логину.
     *
     * @param login логин преподавателя
     * @return true если преподаватель существует, иначе false
     */
    boolean existsByLogin(String login);
}
