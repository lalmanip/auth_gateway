package com.vivance.auth.entity;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class StatusConverter implements AttributeConverter<User.Status, Integer> {

    @Override
    public Integer convertToDatabaseColumn(User.Status status) {
        return status == User.Status.ACTIVE ? 1 : 0;
    }

    @Override
    public User.Status convertToEntityAttribute(Integer value) {
        return (value != null && value == 1) ? User.Status.ACTIVE : User.Status.INACTIVE;
    }
}
