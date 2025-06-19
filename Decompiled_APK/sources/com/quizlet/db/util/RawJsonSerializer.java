package com.quizlet.db.util;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.quizlet.db.data.models.wrappers.RawJsonObject;
import java.io.IOException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class RawJsonSerializer extends JsonSerializer<RawJsonObject> {
    @Override // com.fasterxml.jackson.databind.JsonSerializer
    public final void serialize(RawJsonObject rawJsonObject, JsonGenerator generator, SerializerProvider serializers) throws IOException {
        RawJsonObject value = rawJsonObject;
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(generator, "generator");
        Intrinsics.checkNotNullParameter(serializers, "serializers");
        if (value.getValue() == null) {
            generator.writeNull();
        } else {
            generator.writeRawValue(value.getValue());
        }
    }
}
