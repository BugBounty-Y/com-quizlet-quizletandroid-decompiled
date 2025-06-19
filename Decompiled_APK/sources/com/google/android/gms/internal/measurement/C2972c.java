package com.google.android.gms.internal.measurement;

import java.util.Iterator;
import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.measurement.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2972c implements Iterator {
    public final /* synthetic */ Iterator a;
    public final /* synthetic */ Iterator b;

    public C2972c(Iterator it2, Iterator it3) {
        this.a = it2;
        this.b = it3;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        if (this.a.hasNext()) {
            return true;
        }
        return this.b.hasNext();
    }

    @Override // java.util.Iterator
    public final /* bridge */ /* synthetic */ Object next() {
        Iterator it2 = this.a;
        if (it2.hasNext()) {
            return new C3042q(((Integer) it2.next()).toString());
        }
        Iterator it3 = this.b;
        if (it3.hasNext()) {
            return new C3042q((String) it3.next());
        }
        throw new NoSuchElementException();
    }
}
