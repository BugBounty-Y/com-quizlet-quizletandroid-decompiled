package com.fasterxml.jackson.core.exc;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;

/* loaded from: classes.dex */
public abstract class StreamWriteException extends JsonProcessingException {
    protected transient JsonGenerator _processor;

    public StreamWriteException(String str, JsonGenerator jsonGenerator) {
        super(str, null);
        this._processor = jsonGenerator;
    }

    @Override // com.fasterxml.jackson.core.JsonProcessingException, com.fasterxml.jackson.core.JacksonException
    public JsonGenerator getProcessor() {
        return this._processor;
    }
}
