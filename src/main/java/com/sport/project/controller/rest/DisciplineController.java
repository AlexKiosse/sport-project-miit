package com.sport.project.controller.rest;

import com.sport.project.dto.*;
import com.sport.project.exception.EntityNotFoundException;
import com.sport.project.service.impl.DisciplineServiceImpl;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;

/**
 * REST контроллер для управления учебными дисциплинами
 */
@Tag(name = "Дисциплины", description = "API для управления учебными дисциплинами")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/discipline")
public class DisciplineController {
    private final DisciplineServiceImpl disciplineService;

    @Operation(summary = "Получить все дисциплины", description = "Возвращает список всех учебных дисциплин")
    @ApiResponse(responseCode = "200", description = "Дисциплины успешно получены")
    @GetMapping(path = "/findAll")
    public ResponseEntity<List<DisciplineDTO>> findAll() {
        return ResponseEntity.ok(disciplineService.findAll());
    }

    @Operation(summary = "Получить дисциплину по ID", description = "Возвращает учебную дисциплину по её уникальному идентификатору")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Дисциплина найдена"),
        @ApiResponse(responseCode = "404", description = "Дисциплина не найдена")
    })
    @GetMapping("/{id}")
    public ResponseEntity<DisciplineDTO> findById(
            @Parameter(description = "ID дисциплины", example = "1")
            @PathVariable(name = "id") Integer id) throws com.sport.project.exception.EntityNotFoundException {
        return ResponseEntity.ok(disciplineService.findById(id));
    }

    @Operation(summary = "Получить дисциплину по названию", description = "Возвращает учебную дисциплину по её названию")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Дисциплина найдена"),
        @ApiResponse(responseCode = "404", description = "Дисциплина не найдена")
    })
    @GetMapping("/findByName")
    public ResponseEntity<DisciplineDTO> findByName(
            @Parameter(description = "Название дисциплины", example = "Физическая культура")
            @RequestParam(name = "name") String name) throws com.sport.project.exception.EntityNotFoundException {
        return ResponseEntity.ok(disciplineService.findByName(name));
    }


    @Operation(summary = "Получить занятия по ID дисциплины", description = "Возвращает список занятий по ID учебной дисциплины")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Занятия найдены"),
        @ApiResponse(responseCode = "404", description = "Дисциплина не найдена")
    })
    @GetMapping("/findByDisciplineId/{disciplineId}/lessons")
    public ResponseEntity<List<LessonDTO>> getLessonsByDisciplineId(
            @Parameter(description = "ID дисциплины", example = "1")
            @PathVariable(name = "disciplineId") Integer disciplineId) throws com.sport.project.exception.EntityNotFoundException {
        return ResponseEntity.ok(disciplineService.getLessons(disciplineId));
    }

    @Operation(summary = "Получить занятия по названию дисциплины", description = "Возвращает список занятий по названию учебной дисциплины")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Занятия найдены"),
        @ApiResponse(responseCode = "404", description = "Дисциплина не найдена")
    })
    @GetMapping("/findByDisciplineName/{disciplineName}/lessons")
    public ResponseEntity<List<LessonDTO>> getLessons(
            @Parameter(description = "Название дисциплины", example = "Физическая культура")
            @PathVariable(name = "disciplineName") String disciplineName) throws EntityNotFoundException {
        return ResponseEntity.ok(disciplineService.getLessons(disciplineName));
    }

    @Operation(summary = "Проверить существование дисциплины по названию", description = "Проверяет существование дисциплины по названию")
    @ApiResponse(responseCode = "200", description = "Результат проверки")
    @GetMapping(path = "/isExistsByName")
    public boolean existsByName(
            @Parameter(description = "Название дисциплины", example = "Физическая культура")
            @RequestParam(name = "disciplineName") String disciplineName) {
        return this.disciplineService.existsByName(disciplineName);
    }

    @Operation(summary = "Создать дисциплину через DTO", description = "Создаёт новую учебную дисциплину")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "Дисциплина успешно создана"),
        @ApiResponse(responseCode = "400", description = "Дисциплина с таким названием уже существует")
    })
    @PostMapping(path = "/create")
    public ResponseEntity<DisciplineDTO> create(
            @Parameter(description = "Данные для создания дисциплины")
            @RequestBody DisciplineCreationDTO dto) {
        DisciplineDTO created = disciplineService.create(dto);

        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @Operation(summary = "Создать дисциплину по названию", description = "Создаёт новую учебную дисциплину по названию")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "Дисциплина успешно создана"),
        @ApiResponse(responseCode = "400", description = "Дисциплина с таким названием уже существует")
    })
    @PostMapping(path = "/createByName")
    public ResponseEntity<DisciplineDTO> create(
            @Parameter(description = "Название дисциплины")
            @RequestBody String name) {
        DisciplineDTO created = disciplineService.create(name);

        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @Operation(summary = "Получить количество занятий дисциплины", description = "Возвращает общее количество занятий дисциплины")
    @ApiResponse(responseCode = "200", description = "Количество занятий успешно получено")
    @GetMapping("/lessonsCount/{disciplineId}")
    public Map<String, Integer> getLessonCount(
            @Parameter(description = "ID дисциплины", example = "1")
            @PathVariable(name = "disciplineId") Integer disciplineId) {
        int count = this.disciplineService.getLessonCount(disciplineId);
        return Map.of("lessonCount", count);
    }

    @Operation(summary = "Получить занятия дисциплины по диапазону дат", description = "Возвращает список занятий дисциплины за указанный период")
    @ApiResponse(responseCode = "200", description = "Занятия найдены")
    @GetMapping("/lessonsByDateRange")
    public ResponseEntity<?> getLessonsByDateRange(
            @Parameter(description = "ID дисциплины", example = "1")
            @RequestParam(name = "disciplineId") Integer disciplineId,
            @Parameter(description = "Начальная дата", example = "2024-09-01")
            @RequestParam(name = "from") LocalDate from,
            @Parameter(description = "Конечная дата", example = "2024-09-30")
            @RequestParam(name = "to") LocalDate to
    ) {
        List<LessonDTO> lessons = disciplineService.getLessonsByDateRange(disciplineId, from, to);
        return ResponseEntity.ok(lessons);
    }

    // FIXME - чем отличается от getLessonsByDisciplineId() ? - оба возвращают List<LessonDTO>, где есть препод и его фио
    @Operation(summary = "Получить занятия дисциплины с информацией о преподавателе", description = "Возвращает список занятий с информацией о преподавателе по ID учебной дисциплины")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Занятия дисциплины найдены"),
            @ApiResponse(responseCode = "404", description = "Дисциплина не найдена")
    })
    @GetMapping("/findById/{disciplineId}/lessonsWithTeacher")
    public ResponseEntity<List<LessonDTO>> getLessonsWithTeacher(
            @Parameter(description = "ID дисциплины", example = "1")
            @PathVariable(name = "disciplineId") Integer disciplineId) throws com.sport.project.exception.EntityNotFoundException {
        return ResponseEntity.ok(disciplineService.getLessonsWithTeacher(disciplineId));
    }

    @Operation(summary = "Проверить возможность удаления дисциплины", description = "Возвращает можно ли удалить дисциплину")
    @ApiResponse(responseCode = "200", description = "Дисциплина может быть удалена")
    @GetMapping("/canDelete/{disciplineId}")
    public boolean canDelete(
            @Parameter(description = "ID дисциплина", example = "1")
            @PathVariable(name = "disciplineId") Integer disciplineId) throws EntityNotFoundException {
        return this.disciplineService.canDelete(disciplineId);
    }

    @Operation(summary = "Удалить дисциплину по ID", description = "Удаляет дисциплину по её ID")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Дисциплина успешно удалена"),
            @ApiResponse(responseCode = "404", description = "Дисциплина не найдена")
    })
    @DeleteMapping("/delete/{disciplineId}")
    public ResponseEntity<Void> deleteById(
            @Parameter(description = "ID дисциплина", example = "1")
            @PathVariable(name = "disciplineId") Integer disciplineId) throws EntityNotFoundException {
        disciplineService.deleteById(disciplineId);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Удалить дисциплину по ее названию", description = "Удаляет дисциплину по её названию")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Дисциплина успешно удалена"),
            @ApiResponse(responseCode = "404", description = "Дисциплина не найдена")
    })
    @DeleteMapping("/deleteByName")
    public ResponseEntity<Void> deleteByName(
            @Parameter(description = "Название дисциплины", example = "Физическая культура и спорт")
            @RequestParam(name = "disciplineName") String disciplineName) throws EntityNotFoundException {
        disciplineService.deleteByName(disciplineName);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Обновить название дисциплины", description = "Обновляет название дисциплины и возвращает обновленные данные")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Название дисциплины успешно обновлено"),
            @ApiResponse(responseCode = "404", description = "Дисциплина не найдена")
    })
    @PutMapping("/update/{disciplineId}")
    public ResponseEntity<DisciplineDTO> updateName(
            @Parameter(description = "ID дисциплины", example = "1")
            @PathVariable(name = "disciplineId") Integer disciplineId,
            @Parameter(description = "Название дисциплины", example = "Физическая культура и спорт")
            @RequestParam(name = "disciplineName") String disciplineName
    ) throws EntityNotFoundException {
        disciplineService.updateName(disciplineId, disciplineName);
        return ResponseEntity.accepted().body(disciplineService.findById(disciplineId));
    }
}
