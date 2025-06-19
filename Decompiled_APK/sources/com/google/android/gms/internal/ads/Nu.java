package com.google.android.gms.internal.ads;

import java.util.Iterator;

/* loaded from: classes2.dex */
public final class Nu extends AbstractC2459ou {
    public final transient Object d;

    public Nu(Object obj) {
        obj.getClass();
        this.d = obj;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final int a(Object[] objArr, int i) {
        objArr[i] = this.d;
        return i + 1;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        return this.d.equals(obj);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2459ou, com.google.android.gms.internal.ads.AbstractC2071fu
    public final AbstractC2330lu e() {
        return AbstractC2330lu.s(this.d);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final Pu g() {
        return new C2587ru(this.d);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final boolean h() {
        return false;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2459ou, java.util.Collection, java.util.Set
    public final int hashCode() {
        return this.d.hashCode();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final /* synthetic */ Iterator iterator() {
        return new C2587ru(this.d);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return 1;
    }

    @Override // java.util.AbstractCollection
    public final String toString() {
        return android.support.v4.media.session.a.B("[", this.d.toString(), "]");
    }
}
