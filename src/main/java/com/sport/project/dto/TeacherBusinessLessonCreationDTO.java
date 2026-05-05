package com.sport.project.dto;

import com.sport.project.utils.LocalTimeDeserializer;
import com.sport.project.utils.LocalTimeSerializer;
import lombok.*;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;

import java.time.LocalDate;
import java.time.LocalTime;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class TeacherBusinessLessonCreationDTO {

    private Integer teacherId;
    private String groupName;

    private LocalDate dateOfLesson;

    @JsonSerialize(using = LocalTimeSerializer.class)
    private LocalTime startAt;

    @JsonDeserialize(using = LocalTimeDeserializer.class)
    private LocalTime endAt;
}
