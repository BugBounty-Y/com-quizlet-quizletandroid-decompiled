package com.google.gson.reflect;

import com.google.gson.internal.d;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

/* loaded from: classes2.dex */
public class TypeToken<T> {
    public final Class a;
    public final Type b;
    public final int c;

    public TypeToken() {
        Type genericSuperclass = getClass().getGenericSuperclass();
        if (genericSuperclass instanceof Class) {
            throw new RuntimeException("Missing type parameter.");
        }
        Type typeB = d.b(((ParameterizedType) genericSuperclass).getActualTypeArguments()[0]);
        this.b = typeB;
        this.a = d.h(typeB);
        this.c = typeB.hashCode();
    }

    public final boolean equals(Object obj) {
        if (obj instanceof TypeToken) {
            return d.f(this.b, ((TypeToken) obj).b);
        }
        return false;
    }

    public final int hashCode() {
        return this.c;
    }

    public final String toString() {
        return d.k(this.b);
    }

    public TypeToken(Type type) {
        type.getClass();
        Type typeB = d.b(type);
        this.b = typeB;
        this.a = d.h(typeB);
        this.c = typeB.hashCode();
    }
}
