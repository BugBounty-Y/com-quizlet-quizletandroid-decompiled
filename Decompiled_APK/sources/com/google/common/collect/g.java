package com.google.common.collect;

import java.util.Iterator;
import java.util.ListIterator;

/* loaded from: classes2.dex */
public final class g extends j {
    public final transient j c;

    public g(j jVar) {
        this.c = jVar;
    }

    @Override // com.google.common.collect.j, com.google.common.collect.AbstractC3923f, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        return this.c.contains(obj);
    }

    @Override // java.util.List
    public final Object get(int i) {
        j jVar = this.c;
        com.google.common.base.b.c(i, jVar.size());
        return jVar.get((jVar.size() - 1) - i);
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final boolean h() {
        return this.c.h();
    }

    @Override // com.google.common.collect.j, java.util.List
    public final int indexOf(Object obj) {
        int iLastIndexOf = this.c.lastIndexOf(obj);
        if (iLastIndexOf >= 0) {
            return (r0.size() - 1) - iLastIndexOf;
        }
        return -1;
    }

    @Override // com.google.common.collect.j, com.google.common.collect.AbstractC3923f, java.util.AbstractCollection, java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        return listIterator(0);
    }

    @Override // com.google.common.collect.j, java.util.List
    public final int lastIndexOf(Object obj) {
        int iIndexOf = this.c.indexOf(obj);
        if (iIndexOf >= 0) {
            return (r0.size() - 1) - iIndexOf;
        }
        return -1;
    }

    @Override // com.google.common.collect.j, java.util.List
    public final ListIterator listIterator() {
        return listIterator(0);
    }

    @Override // com.google.common.collect.j
    public final j o() {
        return this.c;
    }

    @Override // com.google.common.collect.j, java.util.List
    /* renamed from: s */
    public final j subList(int i, int i2) {
        j jVar = this.c;
        com.google.common.base.b.e(i, i2, jVar.size());
        return jVar.subList(jVar.size() - i2, jVar.size() - i).o();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.c.size();
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
