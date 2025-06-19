package com.fasterxml.jackson.core;

import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.core.util.RequestPayload;

/* loaded from: classes.dex */
public class JsonParseException extends StreamReadException {
    public JsonParseException(JsonParser jsonParser, String str) {
        this(jsonParser, str, StreamReadException._currentLocation(jsonParser), null);
    }

    @Override // com.fasterxml.jackson.core.exc.StreamReadException, com.fasterxml.jackson.core.JsonProcessingException, java.lang.Throwable
    public String getMessage() {
        return super.getMessage();
    }

    public JsonParseException withRequestPayload(RequestPayload requestPayload) {
        return this;
    }

    public JsonParseException(JsonParser jsonParser, String str, Throwable th) {
        this(jsonParser, str, StreamReadException._currentLocation(jsonParser), th);
    }

    @Override // com.fasterxml.jackson.core.exc.StreamReadException, com.fasterxml.jackson.core.JsonProcessingException, com.fasterxml.jackson.core.JacksonException
    public JsonParser getProcessor() {
        return super.getProcessor();
    }

    public JsonParseException(JsonParser jsonParser, String str, JsonLocation jsonLocation) {
        this(jsonParser, str, jsonLocation, null);
    }

    public JsonParseException(JsonParser jsonParser, String str, JsonLocation jsonLocation, Throwable th) {
        super(jsonParser, str, jsonLocation, th);
    }
}
