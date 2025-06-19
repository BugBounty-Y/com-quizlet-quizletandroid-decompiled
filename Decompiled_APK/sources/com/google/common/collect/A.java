package com.google.common.collect;

/* loaded from: classes2.dex */
public final class A extends o {
    public final transient m d;
    public final transient B e;

    public A(m mVar, B b) {
        this.d = mVar;
        this.e = b;
    }

    @Override // com.google.common.collect.o, com.google.common.collect.AbstractC3923f
    public final j a() {
        return this.e;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final int b(Object[] objArr) {
        return this.e.b(objArr);
    }

    @Override // com.google.common.collect.AbstractC3923f, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        return this.d.get(obj) != null;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final boolean h() {
        return true;
    }

    @Override // com.google.common.collect.AbstractC3923f
    /* renamed from: j */
    public final com.google.android.gms.internal.common.g iterator() {
        return this.e.listIterator(0);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return ((C) this.d).f;
    }

    @Override // com.google.common.collect.o, com.google.common.collect.AbstractC3923f
    public Object writeReplace() {
        return super.writeReplace();
    }
}
