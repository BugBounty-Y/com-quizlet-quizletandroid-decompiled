package com.google.common.collect;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class B extends j {
    public final transient Object[] c;
    public final transient int d;
    public final transient int e;

    public B(Object[] objArr, int i, int i2) {
        this.c = objArr;
        this.d = i;
        this.e = i2;
    }

    @Override // java.util.List
    public final Object get(int i) {
        com.google.common.base.b.c(i, this.e);
        Object obj = this.c[(i * 2) + this.d];
        Objects.requireNonNull(obj);
        return obj;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final boolean h() {
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.e;
    }

    @Override // com.google.common.collect.j, com.google.common.collect.AbstractC3923f
    public Object writeReplace() {
        return super.writeReplace();
    }
}
