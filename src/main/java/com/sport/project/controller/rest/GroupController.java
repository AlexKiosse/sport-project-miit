package com.sport.project.controller.rest;

import com.sport.project.dto.GroupCreationDTO;
import com.sport.project.dto.GroupDTO;
import com.sport.project.dto.StudentDTO;
import com.sport.project.exception.EntityNotFoundException;
import com.sport.project.service.impl.GroupServiceImpl;
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
 * REST контроллер для управления учебными группами
 */
@Tag(name = "Группы", description = "API для управления учебными группами")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/group")
public class GroupController {
    private final GroupServiceImpl groupService;

    @Operation(summary = "Создание группы", description = "Возвращает созданную группу в виде JSON")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Группа создана"),
            @ApiResponse(responseCode = "400", description = "Группа не создана")
    })
    @PostMapping("/create")
    public ResponseEntity<GroupDTO> create(@RequestBody GroupCreationDTO groupCreationDTO) {
        GroupDTO created = groupService.create(groupCreationDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @Operation(summary = "Получить все группы", description = "Возвращает список всех учебных групп")
    @ApiResponse(responseCode = "200", description = "Группы успешно получены")
    @GetMapping("/getAll")
    public ResponseEntity<List<GroupDTO>> getAll() {
        return ResponseEntity.ok(groupService.findAll());
    }

    @Operation(summary = "Получить группу по ID", description = "Возвращает учебную группу по её уникальному идентификатору")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Группа найдена"),
        @ApiResponse(responseCode = "404", description = "Группа не найдена")
    })
    @GetMapping("/{id}")
    public ResponseEntity<GroupDTO> getGroupById(
            @Parameter(description = "ID группы", example = "1")
            @PathVariable("id") Integer id) {
        GroupDTO group = groupService.findById(id);
        return ResponseEntity.ok(group);
    }

    @Operation(summary = "Получить группу по названию", description = "Возвращает учебную группу по её названию")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Группа найдена"),
        @ApiResponse(responseCode = "404", description = "Группа не найдена")
    })
    @GetMapping("/getByName")
    public ResponseEntity<GroupDTO> getGroupByName(
            @Parameter(description = "Название группы", example = "ИУ7-12Б")
            @RequestParam String name) {
        return ResponseEntity.ok(groupService.findByName(name));
    }

    @Operation(summary = "Получить группы по институту", description = "Возвращает список групп по названию института")
    @ApiResponse(responseCode = "200", description = "Группы найдены")
    @GetMapping("/getByInstitute")
    public ResponseEntity<List<GroupDTO>> getGroupByInstitute(
            @Parameter(description = "Название института", example = "ИУ")
            @RequestParam String institute) {
        return ResponseEntity.ok(groupService.findByInstitute(institute));
    }

    @Operation(summary = "Получить студентов группы по ID", description = "Возвращает список студентов учебной группы по её ID")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Студенты найдены"),
        @ApiResponse(responseCode = "404", description = "Группа не найдена")
    })
    @GetMapping("/id/{groupId}/students")
    public ResponseEntity<List<StudentDTO>> getStudentsByGroupId(
            @Parameter(description = "ID группы", example = "1")
            @PathVariable(name = "groupId") Integer groupId) {
        return ResponseEntity.ok(groupService.getStudents(groupId));
    }


    @Operation(summary = "Получить студентов группы по названию", description = "Возвращает список студентов учебной группы по её названию")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Студенты найдены"),
        @ApiResponse(responseCode = "404", description = "Группа не найдена")
    })
    @GetMapping("/name/{groupName}/students")
    public ResponseEntity<List<StudentDTO>> getStudentsByGroupName(
            @Parameter(description = "Название группы", example = "ИУ7-12Б")
            @PathVariable(name = "groupName") String groupName) {
        return ResponseEntity.ok(groupService.getStudents(groupName));
    }

    @Operation(summary = "Получить количество студентов в группе по айди группы", description = "Возвращает количество студентов в группе")
    @ApiResponse(responseCode = "200", description = "Количество студентов успешно получено")
    @GetMapping("/studentsCount/{groupId}")
    public Map<String, Integer> getStudentCount(
            @Parameter(description = "ID группы", example = "1")
            @PathVariable(name = "groupId") Integer groupId) {
        int count = this.groupService.getStudentCount(groupId);
        return Map.of("StudentsInGroupCount", count);
    }

    @Operation(summary = "Проверка, является ли группа пустой (не содержит студентов)", description = "Возвращает true, если группа пустая, иначе false")
    @ApiResponse(responseCode = "200", description = "Группа пустая")
    @GetMapping("/isEmpty/{groupId}")
    public boolean isEmpty(
            @Parameter(description = "ID группы", example = "1")
            @PathVariable(name = "groupId") Integer groupId) throws EntityNotFoundException {
        return this.groupService.isEmpty(groupId);
    }

    @Operation(summary = "Получение студентов группы с информацией о посещаемости за период", description = "Возвращает список студентов с посещаемостью за период")
    @ApiResponse(responseCode = "200", description = "Посещаемость группы за период найдена")
    @GetMapping("/visitsGroupByRange")
    public ResponseEntity<?> getStudentsWithAttendance(
            @Parameter(description = "ID группы", example = "1")
            @RequestParam(name = "groupId") Integer groupId,
            @Parameter(description = "Начальная дата", example = "2024-09-01")
            @RequestParam(name = "from") LocalDate from,
            @Parameter(description = "Конечная дата", example = "2024-09-30")
            @RequestParam(name = "to") LocalDate to
    ) {
        List<StudentDTO> students = groupService.getStudentsWithAttendance(groupId, from, to);
        return ResponseEntity.ok(students);
    }

    @Operation(summary = "Перевод всех студентов из одной группы в другую", description = "Изменяет группу всех студентов по айди ")
    @ApiResponse(responseCode = "200", description = "Группа успешно изменена")
    @PutMapping("/transferStudents")
    public ResponseEntity<Void> transferStudents(
            @Parameter(description = "ID старой группы", example = "1")
            @RequestParam(name = "fromGroupId") Integer fromGroupId,
            @Parameter(description = "ID новой группы", example = "2")
            @RequestParam(name = "toGroupId") Integer toGroupId
    ) throws EntityNotFoundException {
        groupService.transferStudents(fromGroupId, toGroupId);
        return ResponseEntity.accepted().build();
    }

    @Operation(summary = "Удалить группу по ID", description = "Удаляет группу по её ID")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Группа успешно удалена"),
            @ApiResponse(responseCode = "404", description = "Группа не найдена")
    })
    @DeleteMapping("/delete/{groupId}")
    public ResponseEntity<Void> deleteById(
            @Parameter(description = "ID группы", example = "1")
            @PathVariable(name = "groupId") Integer groupId) throws EntityNotFoundException {
        groupService.deleteById(groupId);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Удалить группу по ее названию", description = "Удаляет группу по её названию")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Группа успешно удалена"),
            @ApiResponse(responseCode = "404", description = "Группа не найдена")
    })
    @DeleteMapping("/deleteByName")
    public ResponseEntity<Void> deleteByName(
            @Parameter(description = "Название группы", example = "УВП-111")
            @RequestParam(name = "groupName") String groupName) throws EntityNotFoundException {
        groupService.deleteByName(groupName);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Обновить название группы", description = "Обновляет название группы")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Название группы успешно обновлено"),
            @ApiResponse(responseCode = "404", description = "Группа не найдена")
    })
    @PutMapping("/update/{groupId}/name")
    public ResponseEntity<GroupDTO> updateName(
            @Parameter(description = "ID группы", example = "1")
            @PathVariable(name = "groupId") Integer groupId,
            @Parameter(description = "Название группы", example = "УВП-211")
            @RequestParam(name = "groupName") String groupName
    ) throws EntityNotFoundException {
        return ResponseEntity.ok(groupService.updateName(groupId, groupName));
    }

    @Operation(summary = "Обновить институт группы", description = "Обновляет институт группы")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Институт группы успешно обновлен"),
            @ApiResponse(responseCode = "404", description = "Группа не найдена")
    })
    @PutMapping("/update/{groupId}/institute")
    public ResponseEntity<GroupDTO> updateInstitute(
            @Parameter(description = "ID группы", example = "1")
            @PathVariable(name = "groupId") Integer groupId,
            @Parameter(description = "Институт группы", example = "УВП-211")
            @RequestParam(name = "groupInstitute") String groupInstitute
    ) throws EntityNotFoundException {
        return ResponseEntity.ok(groupService.updateInstitute(groupId, groupInstitute));
    }
}
