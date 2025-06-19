package com.google.android.gms.internal.ads;

import java.util.Iterator;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.ey, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2031ey implements Iterable {
    public final /* synthetic */ List a;
    public final /* synthetic */ List b;

    public C2031ey(List list, List list2) {
        this.a = list;
        this.b = list2;
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        return new C2075fy(this.a.iterator(), this.b.iterator());
    }
}
