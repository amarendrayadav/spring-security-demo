package com.tut.security.springsecuritydemo.security;

public enum ApplicationUserPermission {
    STUDENT_READ("STUDENT:READ"),
    STUDENT_WRITE("STUDENT:WRITE"),
    COURSE_READ("COURSE:READ"),
    COURSE_WRITE("COURSE:WRITE");

    private final String permission;

    ApplicationUserPermission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
