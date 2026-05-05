package com.sport.project.controller.rest;

import com.sport.project.dto.TeacherBusinessLessonCreationDTO;
import com.sport.project.dto.TeacherCreationDTO;
import com.sport.project.dto.TeacherDTO;
import com.sport.project.service.impl.TeacherServiceImpl;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;

/**
 * REST контроллер для управления преподавателями
 */
@Tag(name = "Преподаватели", description = "API для управления преподавателями")
@RestController
@RequestMapping(path = "/api/teachers")
@RequiredArgsConstructor
@Slf4j
public class RestTeacherController {

    private final TeacherServiceImpl teacherService;

    @Operation(summary = "Получить преподавателя по логину", description = "Возвращает преподавателя по его логину")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Преподаватель найден"),
        @ApiResponse(responseCode = "404", description = "Преподаватель не найден")
    })
    @GetMapping(path = "/find-by-login", params = "login")
    public TeacherDTO findByLogin(
            @Parameter(description = "Логин преподавателя", example = "petrov")
            @RequestParam(name = "login") String login) {
        return this.teacherService.findByLogin(login);
    }

    @Operation(summary = "Получить преподавателя по ФИО", description = "Возвращает список преподавателей по ФИО")
    @ApiResponse(responseCode = "200", description = "Преподаватели найдены")
    @GetMapping(path = "/find-by-full-name")
    public List<TeacherDTO> findByFullName(
            @Parameter(description = "Имя преподавателя", example = "Пётр")
            @RequestParam(name = "first-name") String firstName,
            @Parameter(description = "Фамилия преподавателя", example = "Петров")
            @RequestParam(name = "last-name") String lastName,
            @Parameter(description = "Отчество преподавателя", example = "Петрович")
            @RequestParam(name = "patronymic", required = false) String patronymic) {
        return this.teacherService.findByFullName(firstName, lastName, patronymic);
    }

    @Operation(summary = "Получить всех преподавателей", description = "Возвращает список всех преподавателей")
    @ApiResponse(responseCode = "200", description = "Преподаватели успешно получены")
    @GetMapping(path = "/find-all")
    public List<TeacherDTO> findAll() {
        return this.teacherService.findAll();
    }

    @Operation(summary = "Получить всех модераторов", description = "Возвращает список преподавателей с правами модератора")
    @ApiResponse(responseCode = "200", description = "Модераторы успешно получены")
    @GetMapping(path = "/find-all-moderators")
    public List<TeacherDTO> findAllModerators() {
        return this.teacherService.findAllModerators();
    }

    @Operation(summary = "Получить преподавателей по дате занятия", description = "Возвращает список преподавателей, у которых есть занятия в указанную дату")
    @ApiResponse(responseCode = "200", description = "Преподаватели найдены")
    @GetMapping(path = "/get-by-lesson-date")
    public List<TeacherDTO> findByLessonDate(
            @Parameter(description = "Дата занятия", example = "2024-09-01")
            @RequestParam(name = "date") LocalDate date) {
        return this.teacherService.findByLessonsDate(date);
    }

    @Operation(summary = "Проверить существование преподавателя по логину", description = "Проверяет существование преподавателя по логину")
    @ApiResponse(responseCode = "200", description = "Результат проверки")
    @GetMapping(path = "/is-exists-by-login")
    public boolean isExistByLogin(
            @Parameter(description = "Логин преподавателя", example = "petrov")
            @RequestParam(name = "login") String login) {
        return this.teacherService.existsByLogin(login);
    }

    @Operation(summary = "Создать преподавателя", description = "Создаёт нового преподавателя")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "Преподаватель успешно создан"),
        @ApiResponse(responseCode = "400", description = "Преподаватель с таким логином уже существует")
    })
    @PostMapping(path = "/create")
    public ResponseEntity<TeacherDTO> create(
            @Parameter(description = "Данные для создания преподавателя")
            @RequestBody TeacherCreationDTO dto) {
        TeacherDTO created = teacherService.create(dto);

        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @Operation(summary = "Удалить преподавателя по ID")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Преподаватель удален"),
            @ApiResponse(responseCode = "404", description = "Преподаватель не найден")
    })
    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteById(
            @Parameter(description = "ID преподавателя", example = "1")
            @PathVariable("id") Integer id) {
        teacherService.deleteByID(id);
        return ResponseEntity.ok("Teacher with id " + id + " deleted");
    }

    @Operation(summary = "Удалить преподавателя по логину")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Преподаватель удален"),
            @ApiResponse(responseCode = "404", description = "Преподаватель не найден")
    })
    @DeleteMapping("/by-login/{login}")
    public ResponseEntity<String> deleteByLogin(
            @Parameter(description = "Логин преподавателя", example = "petrov")
            @PathVariable("login") String login) {
        teacherService.deleteByLogin(login);
        return ResponseEntity.ok("Teacher with login '" + login + "' deleted");
    }

    @Operation(summary = "Обновить ФИО преподавателя")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "ФИО обновлено"),
            @ApiResponse(responseCode = "404", description = "Преподаватель не найден")
    })
    @PutMapping("/update-full-name")
    public ResponseEntity<String> updateFullName(
            @Parameter(description = "Имя", example = "Петр")
            @RequestParam(value = "firstName", required = false) String firstName,
            @Parameter(description = "Фамилия", example = "Петров")
            @RequestParam(value = "lastName", required = false) String lastName,
            @Parameter(description = "Отчество", example = "Петрович")
            @RequestParam(value = "patronymic", required = false) String patronymic,
            @Parameter(description = "Логин преподавателя", example = "petrov")
            @RequestParam(value = "login") String login) {
        teacherService.updateFullName(firstName, lastName, patronymic, login);
        return ResponseEntity.ok("Full name updated for teacher: " + login);
    }

    @Operation(summary = "Обновить логин преподавателя")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Логин обновлен"),
            @ApiResponse(responseCode = "404", description = "Преподаватель не найден"),
            @ApiResponse(responseCode = "409", description = "Новый логин уже занят")
    })
    @PutMapping("/update-login")
    public ResponseEntity<String> updateLogin(
            @Parameter(description = "Новый логин", example = "petrov_new")
            @RequestParam(value = "newLogin") String newLogin,
            @Parameter(description = "Текущий логин", example = "petrov")
            @RequestParam(value = "oldLogin") String oldLogin) {
        teacherService.updateLogin(newLogin, oldLogin);
        return ResponseEntity.ok("Login updated from '" + oldLogin + "' to '" + newLogin + "'");
    }

    @Operation(summary = "Обновить статус модератора")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Статус модератора обновлен"),
            @ApiResponse(responseCode = "404", description = "Преподаватель не найден")
    })
    @PutMapping("/update-moderator")
    public ResponseEntity<String> updateModerator(
            @Parameter(description = "Логин преподавателя", example = "petrov")
            @RequestParam(value = "login") String login,
            @Parameter(description = "Статус модератора", example = "true")
            @RequestParam(value = "moderator") boolean moderator) {
        teacherService.updateModerator(login, moderator);
        return ResponseEntity.ok("Moderator status updated for teacher: " + login + " -> " + moderator);
    }

    @Operation(summary = "Создать занятие для группы на будущую дату",
            description = "Создает занятие для группы и автоматически создает записи посещений для всех студентов с isExists = false")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Занятие успешно создано"),
            @ApiResponse(responseCode = "404", description = "Преподаватель, дисциплина или группа не найдены"),
            @ApiResponse(responseCode = "400", description = "Некорректные данные запроса")
    })
    @PostMapping("/create-lesson-for-future")
    public ResponseEntity<String> createLessonForFuture(
            @Parameter(description = "Данные для создания занятия")
            @RequestBody TeacherBusinessLessonCreationDTO dto) {

        teacherService.createLessonForFuture(dto);

        return ResponseEntity.ok(String.format(
                "Lesson created for group ID: %s on date: %s with 'not attended' status for all students",
                dto.getGroupName(),
                dto.getDateOfLesson()
        ));
    }
}
