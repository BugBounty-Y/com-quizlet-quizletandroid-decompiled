package com.google.android.gms.internal.ads;

import java.util.Iterator;

/* renamed from: com.google.android.gms.internal.ads.fy, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2075fy implements Iterator {
    public final Iterator a;
    public final Iterator b;

    public /* synthetic */ C2075fy(Iterator it2, Iterator it3) {
        this.a = it2;
        this.b = it3;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.a.hasNext() || this.b.hasNext();
    }

    @Override // java.util.Iterator
    public final Object next() {
        Iterator it2 = this.a;
        return it2.hasNext() ? it2.next() : this.b.next();
    }
}
