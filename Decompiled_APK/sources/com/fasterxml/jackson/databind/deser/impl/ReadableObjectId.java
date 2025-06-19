package com.fasterxml.jackson.databind.deser.impl;

import com.fasterxml.jackson.annotation.ObjectIdGenerator;
import com.fasterxml.jackson.annotation.ObjectIdResolver;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.deser.UnresolvedForwardReference;
import java.io.IOException;
import java.util.LinkedList;

/* loaded from: classes.dex */
public class ReadableObjectId {
    protected final ObjectIdGenerator.IdKey _key;
    protected LinkedList<Referring> _referringProperties;

    public ReadableObjectId(ObjectIdGenerator.IdKey idKey) {
        this._key = idKey;
    }

    public void appendReferring(Referring referring) {
        if (this._referringProperties == null) {
            this._referringProperties = new LinkedList<>();
        }
        this._referringProperties.add(referring);
    }

    public void bindItem(Object obj) throws IOException {
        throw null;
    }

    public Object resolve() {
        throw null;
    }

    public void setResolver(ObjectIdResolver objectIdResolver) {
    }

    public String toString() {
        return String.valueOf(this._key);
    }

    public static abstract class Referring {
        private final Class<?> _beanType;
        private final UnresolvedForwardReference _reference;

        public Referring(UnresolvedForwardReference unresolvedForwardReference, Class<?> cls) {
            this._reference = unresolvedForwardReference;
            this._beanType = cls;
        }

        public Referring(UnresolvedForwardReference unresolvedForwardReference, JavaType javaType) {
            this._reference = unresolvedForwardReference;
            this._beanType = javaType.getRawClass();
        }
    }
}
