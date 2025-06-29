package com.fasterxml.jackson.databind.exc;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonParser;
import java.util.Collection;

/* loaded from: classes.dex */
public class IgnoredPropertyException extends PropertyBindingException {
    public IgnoredPropertyException(JsonParser jsonParser, String str, JsonLocation jsonLocation, Class<?> cls, String str2, Collection<Object> collection) {
        super(jsonParser, str, jsonLocation, cls, str2, collection);
    }

    public static IgnoredPropertyException from(JsonParser jsonParser, Object obj, String str, Collection<Object> collection) {
        Class<?> cls = obj instanceof Class ? (Class) obj : obj.getClass();
        IgnoredPropertyException ignoredPropertyException = new IgnoredPropertyException(jsonParser, AbstractC0147y.e("Ignored field \"", str, "\" (class ", cls.getName(), ") encountered; mapper configured not to allow this"), jsonParser.currentLocation(), cls, str, collection);
        ignoredPropertyException.prependPath(obj, str);
        return ignoredPropertyException;
    }
}
