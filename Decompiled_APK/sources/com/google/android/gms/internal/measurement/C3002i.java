package com.google.android.gms.internal.measurement;

import java.util.Iterator;

/* renamed from: com.google.android.gms.internal.measurement.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3002i implements Iterator {
    public final /* synthetic */ Iterator a;

    public C3002i(Iterator it2) {
        this.a = it2;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.a.hasNext();
    }

    @Override // java.util.Iterator
    public final /* bridge */ /* synthetic */ Object next() {
        return new C3042q((String) this.a.next());
    }
}
