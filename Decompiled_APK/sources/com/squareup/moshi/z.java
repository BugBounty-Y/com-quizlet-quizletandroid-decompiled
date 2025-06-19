package com.squareup.moshi;

import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.Map;

/* loaded from: classes3.dex */
public final class z implements Map.Entry {
    public z a;
    public z b;
    public z c;
    public z d;
    public z e;
    public final Object f;
    public final int g;
    public Object h;
    public int i;

    public z() {
        this.f = null;
        this.g = -1;
        this.e = this;
        this.d = this;
    }

    @Override // java.util.Map.Entry
    public final boolean equals(Object obj) {
        if (obj instanceof Map.Entry) {
            Map.Entry entry = (Map.Entry) obj;
            Object obj2 = this.f;
            if (obj2 != null ? obj2.equals(entry.getKey()) : entry.getKey() == null) {
                Object obj3 = this.h;
                if (obj3 == null) {
                    if (entry.getValue() == null) {
                        return true;
                    }
                } else if (obj3.equals(entry.getValue())) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override // java.util.Map.Entry
    public final Object getKey() {
        return this.f;
    }

    @Override // java.util.Map.Entry
    public final Object getValue() {
        return this.h;
    }

    @Override // java.util.Map.Entry
    public final int hashCode() {
        Object obj = this.f;
        int iHashCode = obj == null ? 0 : obj.hashCode();
        Object obj2 = this.h;
        return (obj2 != null ? obj2.hashCode() : 0) ^ iHashCode;
    }

    @Override // java.util.Map.Entry
    public final Object setValue(Object obj) {
        Object obj2 = this.h;
        this.h = obj;
        return obj2;
    }

    public final String toString() {
        return this.f + SimpleComparison.EQUAL_TO_OPERATION + this.h;
    }

    public z(z zVar, Object obj, int i, z zVar2, z zVar3) {
        this.a = zVar;
        this.f = obj;
        this.g = i;
        this.i = 1;
        this.d = zVar2;
        this.e = zVar3;
        zVar3.d = this;
        zVar2.e = this;
    }
}
