package com.google.common.collect;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3531s4;

/* loaded from: classes2.dex */
public final class E extends o {
    public final transient Object d;

    public E(Object obj) {
        obj.getClass();
        this.d = obj;
    }

    @Override // com.google.common.collect.o, com.google.common.collect.AbstractC3923f
    public final j a() {
        C3922e c3922e = j.b;
        Object[] objArr = {this.d};
        AbstractC3531s4.e(1, objArr);
        return j.k(1, objArr);
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final int b(Object[] objArr) {
        objArr[0] = this.d;
        return 1;
    }

    @Override // com.google.common.collect.AbstractC3923f, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        return this.d.equals(obj);
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final boolean h() {
        return false;
    }

    @Override // com.google.common.collect.o, java.util.Collection, java.util.Set
    public final int hashCode() {
        return this.d.hashCode();
    }

    @Override // com.google.common.collect.AbstractC3923f
    /* renamed from: j */
    public final com.google.android.gms.internal.common.g iterator() {
        return new t(this.d);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return 1;
    }

    @Override // java.util.AbstractCollection
    public final String toString() {
        return "[" + this.d.toString() + ']';
    }

    @Override // com.google.common.collect.o, com.google.common.collect.AbstractC3923f
    public Object writeReplace() {
        return super.writeReplace();
    }
}
