package com.fasterxml.jackson.databind.deser;

import android.support.v4.media.session.a;
import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.deser.impl.ReadableObjectId;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public class UnresolvedForwardReference extends JsonMappingException {
    private ReadableObjectId _roid;
    private List<Object> _unresolvedIds;

    public UnresolvedForwardReference(JsonParser jsonParser, String str, JsonLocation jsonLocation, ReadableObjectId readableObjectId) {
        super(jsonParser, str, jsonLocation);
        this._roid = readableObjectId;
    }

    @Override // com.fasterxml.jackson.databind.JsonMappingException, com.fasterxml.jackson.core.JsonProcessingException, java.lang.Throwable
    public String getMessage() {
        String message = super.getMessage();
        if (this._unresolvedIds == null) {
            return message;
        }
        StringBuilder sb = new StringBuilder(message);
        Iterator<Object> it2 = this._unresolvedIds.iterator();
        if (it2.hasNext()) {
            throw a.d(it2);
        }
        sb.append('.');
        return sb.toString();
    }

    public ReadableObjectId getRoid() {
        return this._roid;
    }

    @Override // java.lang.Throwable
    public synchronized UnresolvedForwardReference fillInStackTrace() {
        return this;
    }
}
