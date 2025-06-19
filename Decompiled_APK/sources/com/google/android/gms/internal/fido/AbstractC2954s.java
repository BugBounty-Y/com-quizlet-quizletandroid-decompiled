package com.google.android.gms.internal.fido;

import java.util.Collections;
import java.util.Comparator;
import java.util.NavigableSet;
import java.util.SortedSet;

/* renamed from: com.google.android.gms.internal.fido.s, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2954s extends AbstractC2951o implements NavigableSet, C {
    public final transient Comparator d;
    public transient AbstractC2954s e;

    public AbstractC2954s(Comparator comparator) {
        this.d = comparator;
    }

    public static C2961z s(Comparator comparator) {
        if (C2957v.b.equals(comparator)) {
            return C2961z.g;
        }
        C2945i c2945i = AbstractC2949m.b;
        return new C2961z(C2959x.e, comparator);
    }

    public final void addFirst(Object obj) {
        throw new UnsupportedOperationException();
    }

    public final void addLast(Object obj) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.SortedSet
    public final Comparator comparator() {
        return this.d;
    }

    @Override // java.util.SortedSet
    public abstract Object first();

    public final Object getFirst() {
        return first();
    }

    public final Object getLast() {
        return last();
    }

    @Override // java.util.NavigableSet, java.util.SortedSet
    public final SortedSet headSet(Object obj) {
        obj.getClass();
        C2961z c2961z = (C2961z) this;
        return c2961z.v(0, c2961z.t(obj, false));
    }

    @Override // java.util.SortedSet
    public abstract Object last();

    @Override // java.util.NavigableSet
    /* renamed from: n, reason: merged with bridge method [inline-methods] */
    public final AbstractC2954s descendingSet() {
        AbstractC2954s abstractC2954sS = this.e;
        if (abstractC2954sS == null) {
            C2961z c2961z = (C2961z) this;
            Comparator comparatorReverseOrder = Collections.reverseOrder(c2961z.d);
            abstractC2954sS = c2961z.isEmpty() ? s(comparatorReverseOrder) : new C2961z(c2961z.f.h(), comparatorReverseOrder);
            this.e = abstractC2954sS;
            abstractC2954sS.e = this;
        }
        return abstractC2954sS;
    }

    @Override // java.util.NavigableSet
    /* renamed from: o, reason: merged with bridge method [inline-methods] */
    public final C2961z subSet(Object obj, boolean z, Object obj2, boolean z2) {
        obj.getClass();
        obj2.getClass();
        if (this.d.compare(obj, obj2) > 0) {
            throw new IllegalArgumentException();
        }
        C2961z c2961z = (C2961z) this;
        C2961z c2961zV = c2961z.v(c2961z.u(obj, z), c2961z.f.size());
        return c2961zV.v(0, c2961zV.t(obj2, z2));
    }

    @Override // java.util.NavigableSet
    public final Object pollFirst() {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.NavigableSet
    public final Object pollLast() {
        throw new UnsupportedOperationException();
    }

    public final Object removeFirst() {
        throw new UnsupportedOperationException();
    }

    public final Object removeLast() {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.NavigableSet, java.util.SortedSet
    public final /* bridge */ /* synthetic */ SortedSet subSet(Object obj, Object obj2) {
        return subSet(obj, true, obj2, false);
    }

    @Override // java.util.NavigableSet, java.util.SortedSet
    public final SortedSet tailSet(Object obj) {
        obj.getClass();
        C2961z c2961z = (C2961z) this;
        return c2961z.v(c2961z.u(obj, true), c2961z.f.size());
    }

    @Override // java.util.NavigableSet
    public final NavigableSet headSet(Object obj, boolean z) {
        obj.getClass();
        C2961z c2961z = (C2961z) this;
        return c2961z.v(0, c2961z.t(obj, z));
    }

    @Override // java.util.NavigableSet
    public final NavigableSet tailSet(Object obj, boolean z) {
        obj.getClass();
        C2961z c2961z = (C2961z) this;
        return c2961z.v(c2961z.u(obj, z), c2961z.f.size());
    }
}
