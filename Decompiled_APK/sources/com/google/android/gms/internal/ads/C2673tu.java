package com.google.android.gms.internal.ads;

import com.google.common.base.Function;
import java.io.Serializable;
import java.util.AbstractCollection;
import java.util.AbstractList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.RandomAccess;

/* renamed from: com.google.android.gms.internal.ads.tu, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2673tu extends AbstractList implements RandomAccess, Serializable {
    public final /* synthetic */ int a = 0;
    public final Collection b;
    public final Object c;

    /* JADX WARN: Multi-variable type inference failed */
    public C2673tu(List list, InterfaceC2544qt interfaceC2544qt) {
        list.getClass();
        this.b = (AbstractCollection) list;
        this.c = interfaceC2544qt;
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.util.AbstractCollection, java.util.List] */
    @Override // java.util.AbstractList, java.util.List
    public final Object get(int i) {
        switch (this.a) {
            case 0:
                return ((InterfaceC2544qt) this.c).apply(((AbstractCollection) this.b).get(i));
            default:
                return ((Function) this.c).apply(((List) this.b).get(i));
        }
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.util.AbstractCollection, java.util.List] */
    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean isEmpty() {
        switch (this.a) {
            case 0:
                return ((AbstractCollection) this.b).isEmpty();
            default:
                return ((List) this.b).isEmpty();
        }
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.List
    public final Iterator iterator() {
        switch (this.a) {
        }
        return listIterator();
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [java.util.AbstractCollection, java.util.List] */
    @Override // java.util.AbstractList, java.util.List
    public final ListIterator listIterator(int i) {
        switch (this.a) {
            case 0:
                return new C2630su(this, ((AbstractCollection) this.b).listIterator(i), 0);
            default:
                return new com.google.common.collect.u(this, ((List) this.b).listIterator(i), 0);
        }
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.util.AbstractCollection, java.util.List] */
    @Override // java.util.AbstractList, java.util.List
    public final Object remove(int i) {
        switch (this.a) {
            case 0:
                return ((InterfaceC2544qt) this.c).apply(((AbstractCollection) this.b).remove(i));
            default:
                return ((Function) this.c).apply(((List) this.b).remove(i));
        }
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.util.AbstractCollection, java.util.List] */
    @Override // java.util.AbstractList
    public final void removeRange(int i, int i2) {
        switch (this.a) {
            case 0:
                ((AbstractCollection) this.b).subList(i, i2).clear();
                break;
            default:
                ((List) this.b).subList(i, i2).clear();
                break;
        }
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.util.AbstractCollection, java.util.List] */
    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        switch (this.a) {
            case 0:
                return ((AbstractCollection) this.b).size();
            default:
                return ((List) this.b).size();
        }
    }

    public C2673tu(List list, Function function) {
        list.getClass();
        this.b = list;
        this.c = function;
    }
}
