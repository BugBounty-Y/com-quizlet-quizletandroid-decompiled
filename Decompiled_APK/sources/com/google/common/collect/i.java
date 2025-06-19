package com.google.common.collect;

import java.util.Iterator;
import java.util.ListIterator;

/* loaded from: classes2.dex */
public final class i extends j {
    public final transient int c;
    public final transient int d;
    public final /* synthetic */ j e;

    public i(j jVar, int i, int i2) {
        this.e = jVar;
        this.c = i;
        this.d = i2;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final Object[] c() {
        return this.e.c();
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final int e() {
        return this.e.g() + this.c + this.d;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final int g() {
        return this.e.g() + this.c;
    }

    @Override // java.util.List
    public final Object get(int i) {
        com.google.common.base.b.c(i, this.d);
        return this.e.get(i + this.c);
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final boolean h() {
        return true;
    }

    @Override // com.google.common.collect.j, com.google.common.collect.AbstractC3923f, java.util.AbstractCollection, java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        return listIterator(0);
    }

    @Override // com.google.common.collect.j, java.util.List
    public final ListIterator listIterator() {
        return listIterator(0);
    }

    @Override // com.google.common.collect.j, java.util.List
    /* renamed from: s */
    public final j subList(int i, int i2) {
        com.google.common.base.b.e(i, i2, this.d);
        int i3 = this.c;
        return this.e.subList(i + i3, i2 + i3);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }

    @Override // com.google.common.collect.j, com.google.common.collect.AbstractC3923f
    public Object writeReplace() {
        return super.writeReplace();
    }

    @Override // com.google.common.collect.j, java.util.List
    public final /* bridge */ /* synthetic */ ListIterator listIterator(int i) {
        return listIterator(i);
    }
}
