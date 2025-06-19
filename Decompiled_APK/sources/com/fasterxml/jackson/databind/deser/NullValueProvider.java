package com.fasterxml.jackson.databind.deser;

import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonMappingException;

/* loaded from: classes.dex */
public interface NullValueProvider {
    default Object getAbsentValue(DeserializationContext deserializationContext) throws JsonMappingException {
        return getNullValue(deserializationContext);
    }

    Object getNullValue(DeserializationContext deserializationContext) throws JsonMappingException;
}
