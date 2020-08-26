package com.tut.security.springsecuritydemo.student;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Student {
    private Integer studentId;
    private String name;
}
