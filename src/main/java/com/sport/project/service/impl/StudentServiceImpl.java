package com.sport.project.service.impl;

import com.sport.project.dao.entity.*;
import com.sport.project.dao.repository.GroupRepository;
import com.sport.project.dao.repository.HealthGroupRepository;
import com.sport.project.dao.repository.StudentRepository;
import com.sport.project.dto.StudentCreationDTO;
import com.sport.project.dto.StudentDTO;
import com.sport.project.exception.EntityAlreadyExistsException;
import com.sport.project.exception.EntityNotFoundException;
import com.sport.project.mapper.Mapper;
import com.sport.project.service.StudentService;
import com.sport.project.service.interfaces.student.StudentBusinessService;
import com.sport.project.service.interfaces.student.StudentCreationService;
import com.sport.project.service.interfaces.student.StudentDeletingService;
import com.sport.project.service.interfaces.student.StudentUpdatingService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class StudentServiceImpl implements
        StudentService, StudentCreationService, StudentBusinessService, StudentDeletingService, StudentUpdatingService {

    private final StudentRepository studentRepository;
    private final HealthGroupRepository healthGroupRepository;
    private final GroupRepository groupRepository;

    @Override
    public StudentDTO findById(Integer id) throws EntityNotFoundException {
        StudentEntity entity = this.studentRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException(String.format("Student with id %s not found", id)));

        return Mapper.map(entity);
    }

    @Override
    public StudentDTO findByLogin(String login) throws EntityNotFoundException {
        StudentEntity entity = this.studentRepository.findByLogin(login)
                .orElseThrow(() -> new EntityNotFoundException(String.format("Student with login %s not found", login)));

        return Mapper.map(entity);
    }

    @Override
    public List<StudentDTO> findByFullName(String firstName, String lastName, String patronymic) throws EntityNotFoundException {
        List<StudentEntity> entity = this.studentRepository.findByFullNameFirstNameAndFullNameLastNameAndFullNamePatronymic
                (firstName, lastName, patronymic);
        return entity.stream()
                .map(Mapper::map)
                .toList();
    }

    @Override
    public List<StudentDTO> findByFirstNameAndLastName(String firstName, String lastName) {
        return this.studentRepository.findByFullName_FirstNameAndFullName_LastName(firstName, lastName)
                .stream()
                .map(Mapper::map)
                .toList();
    }

    @Override
    public List<StudentDTO> findAll() {
        return this.studentRepository
                .findAll()
                .stream()
                .map(Mapper::map)
                .toList();
    }

    @Override
    public List<StudentDTO> findByGroup(Integer groupId) {
        return this.studentRepository
                .findByGroupId(groupId)
                .stream()
                .map(Mapper::map)
                .toList();
    }

    @Override
    public List<StudentDTO> findBySection(Integer sectionId) {
        return this.studentRepository
                .findBySectionId(sectionId)
                .stream()
                .map(Mapper::map)
                .toList();
    }

    @Override
    public List<StudentDTO> findByHealthGroup(Integer healthGroupId) {
        return this.studentRepository
                .findByHealthGroupId(healthGroupId)
                .stream()
                .map(Mapper::map)
                .toList();
    }

    @Override
    public boolean existsByLogin(String login) {
        return this.studentRepository
                .existsByLogin(login);
    }

    @Override
    @Transactional
    public StudentDTO create(StudentCreationDTO dto) throws EntityAlreadyExistsException {

        log.info("=== DEBUG CREATE STUDENT ===");
        log.info("login: {}", dto.getLogin());
        log.info("healthGroupId: {}", dto.getHealthGroupId());
        log.info("groupId: {}", dto.getGroupId());
        log.info("birthday: {}", dto.getBirthday());
        log.info("============================");

        final String studentLogin = dto.getLogin();
        final String password = dto.getPassword();

        final String firstName = dto.getFirstName();
        final String lastName = dto.getLastName();
        final String patronymic = dto.getPatronymic();
        final LocalDate birthday = dto.getBirthday();

        HealthGroupsEntity healthGroup = this.healthGroupRepository.findById(dto.getHealthGroupId())
                .orElseThrow(() -> new EntityNotFoundException("Health group not found"));

        GroupEntity group = this.groupRepository.findById(dto.getGroupId())
                .orElseThrow(() -> new EntityNotFoundException("Group not found"));

        if (this.existsByLogin(studentLogin)) {
            throw new EntityAlreadyExistsException(
                    String.format("Student with login '%s' already exists", studentLogin)
            );
        }

        StudentEntity entity = StudentEntity.builder()
                .login(studentLogin)
                .passwordHash(password)
                .firstName(firstName)
                .lastName(lastName)
                .patronymic(patronymic)
                .birthday(birthday)
                .healthGroup(healthGroup)
                .group(group)
                .build();

        StudentEntity saved = studentRepository.save(entity);

        return Mapper.map(saved);
    }

    @Override
    public Map<LocalDate, String> getStudentSchedule(String login) {
        StudentEntity student = studentRepository.findByLogin(login)
                .orElseThrow(() -> new EntityNotFoundException("Student with login " + login + " not found"));

        Map<LocalDate, String> schedule = new HashMap<>();

        for (VisitsEntity visit : student.getVisits()) {
            LessonsEntity lesson = visit.getLessons();
            LocalDate lessonDate = lesson.getDateOfLesson();

            schedule.put(lessonDate, lesson.getDiscipline().getName());
        }

        return schedule;
    }

    @Override
    @Transactional
    public void deleteByID(int id) throws EntityNotFoundException {
        StudentEntity student = studentRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Student with ID " + id + " not found"));

        studentRepository.delete(student);
    }

    @Override
    @Transactional
    public void deleteByLogin(String login) throws EntityNotFoundException {
        StudentEntity student = studentRepository.findByLogin(login)
                .orElseThrow(() -> new EntityNotFoundException("Student with login " + login + " not found"));

        studentRepository.delete(student);
    }

    @Override
    @Transactional
    public void updateFullName(String firstName, String lastName, String patronymic, String login) throws EntityNotFoundException {
        StudentEntity student = studentRepository.findByLogin(login)
                .orElseThrow(() -> new EntityNotFoundException("Student with login " + login + " not found"));

        String oldFirstName = student.getFullName().getFirstName();
        String oldLastName = student.getFullName().getLastName();
        String oldPatronymic = student.getFullName().getPatronymic();
        log.info("Updating student full name: {} {} {} (login: {}) -> new: {} {} {}",
                oldLastName, oldFirstName, oldPatronymic != null ? oldPatronymic : "",
                login,
                lastName != null ? lastName : oldLastName,
                firstName != null ? firstName : oldFirstName,
                patronymic != null ? patronymic : (oldPatronymic != null ? oldPatronymic : ""));

        if (firstName != null && !firstName.isBlank()) {
            student.getFullName().setFirstName(firstName);
        }
        if (lastName != null && !lastName.isBlank()) {
            student.getFullName().setLastName(lastName);
        }
        if (patronymic != null && !patronymic.isBlank()) {
            student.getFullName().setPatronymic(patronymic);
        }

        log.info("Updated student full name: {} {} {} (login: {})",
                student.getFullName().getLastName(),
                student.getFullName().getFirstName(),
                student.getFullName().getPatronymic() != null ? student.getFullName().getPatronymic() : "",
                login);
    }

    @Override
    @Transactional
    public void updateLogin(String newLogin, String oldLogin) throws EntityNotFoundException, EntityAlreadyExistsException {
        StudentEntity student = studentRepository.findByLogin(oldLogin)
                .orElseThrow(() -> new EntityNotFoundException("Student with login " + oldLogin + " not found"));

        if (existsByLogin(newLogin)) {
            throw new EntityAlreadyExistsException("Login '" + newLogin + "' is already taken");
        }

        student.setLogin(newLogin);
        log.info("Updated login for student: {} -> {}", oldLogin, newLogin);
    }

    @Override
    @Transactional
    public void updateHealthGroup(int newHealthGroup, String login) throws EntityNotFoundException {
        StudentEntity student = studentRepository.findByLogin(login)
                .orElseThrow(() -> new EntityNotFoundException("Student with login '" + login + "' not found"));

        HealthGroupsEntity healthGroup = healthGroupRepository.findById(newHealthGroup)
                .orElseThrow(() -> new EntityNotFoundException("Health group with id '" + newHealthGroup + "' not found"));

        student.setHealthGroup(healthGroup);
    }
}
