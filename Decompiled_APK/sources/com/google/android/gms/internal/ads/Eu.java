package com.google.android.gms.internal.ads;

import java.util.Iterator;

/* loaded from: classes2.dex */
public final class Eu extends AbstractC2459ou {
    public final transient Gu d;
    public final transient Fu e;

    public Eu(Gu gu, Fu fu) {
        this.d = gu;
        this.e = fu;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final int a(Object[] objArr, int i) {
        return this.e.a(objArr, i);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        return this.d.get(obj) != null;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2459ou, com.google.android.gms.internal.ads.AbstractC2071fu
    public final AbstractC2330lu e() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final Pu g() {
        return this.e.listIterator(0);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final boolean h() {
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final /* synthetic */ Iterator iterator() {
        return this.e.listIterator(0);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return this.d.f;
    }
}
