package com.google.common.collect;

import com.google.android.gms.internal.ads.C2673tu;
import com.google.android.gms.internal.ads.C2716uu;
import com.google.common.base.Function;
import java.util.AbstractList;
import java.util.ListIterator;

/* loaded from: classes2.dex */
public final class u extends F implements ListIterator {
    public final /* synthetic */ int b;
    public final /* synthetic */ AbstractList c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ u(AbstractList abstractList, ListIterator listIterator, int i) {
        super(listIterator);
        this.b = i;
        this.c = abstractList;
    }

    @Override // com.google.common.collect.F
    public final Object a(Object obj) {
        switch (this.b) {
            case 0:
                return ((Function) ((C2673tu) this.c).c).apply(obj);
            default:
                return ((Function) ((C2716uu) this.c).c).apply(obj);
        }
    }

    @Override // java.util.ListIterator
    public final void add(Object obj) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.ListIterator
    public final boolean hasPrevious() {
        return ((ListIterator) this.a).hasPrevious();
    }

    @Override // java.util.ListIterator
    public final int nextIndex() {
        return ((ListIterator) this.a).nextIndex();
    }

    @Override // java.util.ListIterator
    public final Object previous() {
        return a(((ListIterator) this.a).previous());
    }

    @Override // java.util.ListIterator
    public final int previousIndex() {
        return ((ListIterator) this.a).previousIndex();
    }

    @Override // java.util.ListIterator
    public final void set(Object obj) {
        throw new UnsupportedOperationException();
    }
}
