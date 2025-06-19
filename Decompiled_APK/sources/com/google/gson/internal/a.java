package com.google.gson.internal;

import java.io.Serializable;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Type;

/* loaded from: classes2.dex */
public final class a implements GenericArrayType, Serializable {
    public final Type a;

    public a(Type type) {
        this.a = d.b(type);
    }

    public final boolean equals(Object obj) {
        return (obj instanceof GenericArrayType) && d.f(this, (GenericArrayType) obj);
    }

    @Override // java.lang.reflect.GenericArrayType
    public final Type getGenericComponentType() {
        return this.a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return d.k(this.a) + "[]";
    }
}
