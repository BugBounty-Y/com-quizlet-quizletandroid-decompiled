package com.google.android.gms.internal.ads;

import java.util.Iterator;
import java.util.Map;

/* loaded from: classes2.dex */
public final class Du extends AbstractC2459ou {
    public final transient Gu d;
    public final transient Object[] e;
    public final transient int f;

    public Du(Gu gu, Object[] objArr, int i) {
        this.d = gu;
        this.e = objArr;
        this.f = i;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final int a(Object[] objArr, int i) {
        return e().a(objArr, i);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        if (obj instanceof Map.Entry) {
            Map.Entry entry = (Map.Entry) obj;
            Object key = entry.getKey();
            Object value = entry.getValue();
            if (value != null && value.equals(this.d.get(key))) {
                return true;
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final Pu g() {
        return e().listIterator(0);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final boolean h() {
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final /* synthetic */ Iterator iterator() {
        return e().listIterator(0);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2459ou
    public final AbstractC2330lu m() {
        return new Cu(this);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return this.f;
    }
}
