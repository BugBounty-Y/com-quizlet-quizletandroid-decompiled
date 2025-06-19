package com.google.common.collect;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class x extends j {
    public static final x e = new x(new Object[0], 0);
    public final transient Object[] c;
    public final transient int d;

    public x(Object[] objArr, int i) {
        this.c = objArr;
        this.d = i;
    }

    @Override // com.google.common.collect.j, com.google.common.collect.AbstractC3923f
    public final int b(Object[] objArr) {
        Object[] objArr2 = this.c;
        int i = this.d;
        System.arraycopy(objArr2, 0, objArr, 0, i);
        return i;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final Object[] c() {
        return this.c;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final int e() {
        return this.d;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final int g() {
        return 0;
    }

    @Override // java.util.List
    public final Object get(int i) {
        com.google.common.base.b.c(i, this.d);
        Object obj = this.c[i];
        Objects.requireNonNull(obj);
        return obj;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final boolean h() {
        return false;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }

    @Override // com.google.common.collect.j, com.google.common.collect.AbstractC3923f
    public Object writeReplace() {
        return super.writeReplace();
    }
}
