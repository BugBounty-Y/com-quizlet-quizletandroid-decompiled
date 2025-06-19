package com.fasterxml.jackson.databind.exc;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.PropertyName;
import com.fasterxml.jackson.databind.util.ClassUtil;

/* loaded from: classes.dex */
public class InvalidNullException extends MismatchedInputException {
    protected final PropertyName _propertyName;

    public InvalidNullException(JsonParser jsonParser, String str, PropertyName propertyName) {
        super(jsonParser, str);
        this._propertyName = propertyName;
    }

    public static InvalidNullException from(DeserializationContext deserializationContext, PropertyName propertyName, JavaType javaType) {
        InvalidNullException invalidNullException = new InvalidNullException(deserializationContext, AbstractC0147y.d("Invalid `null` value encountered for property ", ClassUtil.quotedOr(propertyName, "<UNKNOWN>")), propertyName);
        if (javaType != null) {
            invalidNullException.setTargetType(javaType);
        }
        return invalidNullException;
    }

    public InvalidNullException(DeserializationContext deserializationContext, String str, PropertyName propertyName) {
        this(deserializationContext == null ? null : deserializationContext.getParser(), str, propertyName);
    }
}
