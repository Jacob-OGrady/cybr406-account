package com.cybr406.account.util;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestUtil {

    public static Class<?> assertClassExists(String className) {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("You need to create a class called " + className, e);
        }
    }

    public static void assertClassExtends(String className, Class<?> baseClass) {
        Class<?> clazz = assertClassExists(className);
        assertTrue(baseClass.isAssignableFrom(clazz), String.format(
                "%s must extend %s", className, baseClass.getCanonicalName()));
    }

    public static <T extends Annotation> T assertClassAnnotationIsPresent(String className, Class<T> annotationClass) {
        Class<?> clazz = assertClassExists(className);
        List<Annotation> annotations = Arrays.asList(clazz.getAnnotations());
        T annotation = clazz.getAnnotation(annotationClass);
        assertNotNull(annotation, String.format(
                "%s must be annotated with %s at the class level",
                className,
                annotationClass.getCanonicalName()));
        return annotation;
    }

    public static void assertClassAnnotationIsPresent(String className, String annotationName, String message) {
        Class<?> clazz = assertClassExists(className);
        List<Annotation> annotations = Arrays.asList(clazz.getAnnotations());

        Annotation annotation = annotations.stream()
                .filter(a -> a.annotationType().getName().equals(annotationName))
                .findFirst()
                .orElse(null);

        assertNotNull(annotation, message);
    }

    public static <T extends Annotation> void assertMethodAnnotationIsPresent(
            String hint, String className, Class<T> annotationClass, String methodName, Class<?>... args)  throws NoSuchMethodException {
        Method method = assertClassDeclaresMethod(hint, className, methodName, args);
        Annotation annotation = method.getAnnotation(annotationClass);
        assertNotNull(annotation, String.format(
                "%s must be annotated with %s at the method level\nHINT: %s",
                methodName,
                annotationClass.getCanonicalName(),
                hint));
    }

    public static Method assertClassDeclaresMethod(String hint, String className, String methodName, Class<?>... args) throws NoSuchMethodException {
        Class<?> clazz = assertClassExists(className);
        try {
            return clazz.getDeclaredMethod(methodName, args);
        } catch (NoSuchMethodException ignored) {
            throw new NoSuchMethodException(String.format(
                    "Expected %s to contain a method named \"%s\" with arguments (%s)\nHINT: %s",
                    className,
                    methodName,
                    Arrays.stream(args).map(Class::getCanonicalName).collect(Collectors.joining(", ")),
                    hint));
        }
    }

    public static Field assertFieldExists(String hint, String className, Class<?> expectedFieldType, String fieldName) throws NoSuchFieldException {
        Class<?> clazz = assertClassExists(className);
        try {
            Field field = clazz.getDeclaredField(fieldName);
            if (!field.getType().equals(expectedFieldType)) {
                throw new IllegalArgumentException(String.format(
                        "Expected field named \"%s\" with type %s in class %s\nHINT: %s",
                        fieldName,
                        expectedFieldType.getCanonicalName(),
                        className,
                        hint));
            }
            return field;
        } catch (NoSuchFieldException e) {
            throw new NoSuchFieldException(String.format(
                    "Expected field named \"%s\" with type %s in class %s\nHINT: %s",
                    fieldName,
                    expectedFieldType.getCanonicalName(),
                    className,
                    hint));
        }
    }

    public static <T extends Annotation> T assertFieldAnnotationExists(String hint, Field field, Class<T> annotationClass) {
        T annotation = field.getAnnotation(annotationClass);
        if (annotation == null) {
            throw new IllegalArgumentException(String.format(
                    "Expected the field \"%s\" to be annotated with @%s\nHINT: %s",
                    field.getName(),
                    annotationClass.getSimpleName(),
                    hint));
        }
        return annotation;
    }

}
