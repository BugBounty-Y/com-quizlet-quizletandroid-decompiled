package com.google.android.gms.internal.ads;

import java.util.List;
import java.util.ListIterator;

/* loaded from: classes2.dex */
public final class Qt extends It implements ListIterator {
    public final /* synthetic */ Rt e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Qt(Rt rt) {
        super(rt);
        this.e = rt;
    }

    @Override // java.util.ListIterator
    public final void add(Object obj) {
        Rt rt = this.e;
        boolean zIsEmpty = rt.isEmpty();
        a();
        ((ListIterator) this.b).add(obj);
        ((C2845xu) rt.g).e++;
        if (zIsEmpty) {
            rt.a();
        }
    }

    @Override // java.util.ListIterator
    public final boolean hasPrevious() {
        a();
        return ((ListIterator) this.b).hasPrevious();
    }

    @Override // java.util.ListIterator
    public final int nextIndex() {
        a();
        return ((ListIterator) this.b).nextIndex();
    }

    @Override // java.util.ListIterator
    public final Object previous() {
        a();
        return ((ListIterator) this.b).previous();
    }

    @Override // java.util.ListIterator
    public final int previousIndex() {
        a();
        return ((ListIterator) this.b).previousIndex();
    }

    @Override // java.util.ListIterator
    public final void set(Object obj) {
        a();
        ((ListIterator) this.b).set(obj);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Qt(Rt rt, int i) {
        super(rt, ((List) rt.c).listIterator(i));
        this.e = rt;
    }
}
