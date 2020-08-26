package com.tut.security.springsecuritydemo.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Andy Roberts"),
            new Student(2, "Judy Roberts"),
            new Student(3, "Ana Smith")
    );

    @GetMapping(path = "/{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId) {
        return STUDENTS.stream()
                .filter(s -> s.getStudentId().equals(studentId))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("studentId " + studentId + " not found!"));
    }
}
