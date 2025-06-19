package com.fasterxml.jackson.databind.ser.impl;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import java.io.IOException;
import java.util.Map;

/* loaded from: classes.dex */
public class MapEntryAsPOJOSerializer extends StdSerializer<Map.Entry<?, ?>> {
    public MapEntryAsPOJOSerializer(JavaType javaType) {
        super(javaType);
    }

    public static MapEntryAsPOJOSerializer create(SerializerProvider serializerProvider, JavaType javaType) {
        return new MapEntryAsPOJOSerializer(javaType);
    }

    @Override // com.fasterxml.jackson.databind.ser.std.StdSerializer, com.fasterxml.jackson.databind.JsonSerializer
    public void serialize(Map.Entry<?, ?> entry, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartObject(entry);
        serializerProvider.defaultSerializeField("key", entry.getKey(), jsonGenerator);
        serializerProvider.defaultSerializeField("value", entry.getValue(), jsonGenerator);
        jsonGenerator.writeEndObject();
    }
}
