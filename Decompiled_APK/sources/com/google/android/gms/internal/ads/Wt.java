package com.google.android.gms.internal.ads;

import java.util.AbstractSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class Wt extends AbstractSet {
    public final /* synthetic */ int a;
    public final /* synthetic */ Zt b;

    public /* synthetic */ Wt(Zt zt, int i) {
        this.a = i;
        this.b = zt;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final void clear() {
        switch (this.a) {
            case 0:
                this.b.clear();
                break;
            default:
                this.b.clear();
                break;
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        switch (this.a) {
            case 0:
                Zt zt = this.b;
                Map mapE = zt.e();
                if (mapE != null) {
                    return mapE.entrySet().contains(obj);
                }
                if (obj instanceof Map.Entry) {
                    Map.Entry entry = (Map.Entry) obj;
                    int iJ = zt.j(entry.getKey());
                    if (iJ != -1 && AbstractC2457os.l(zt.d()[iJ], entry.getValue())) {
                        return true;
                    }
                }
                return false;
            default:
                return this.b.containsKey(obj);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                Zt zt = this.b;
                Map mapE = zt.e();
                return mapE != null ? mapE.entrySet().iterator() : new Vt(zt, 1);
            default:
                Zt zt2 = this.b;
                Map mapE2 = zt2.e();
                return mapE2 != null ? mapE2.keySet().iterator() : new Vt(zt2, 0);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean remove(Object obj) {
        switch (this.a) {
            case 0:
                Zt zt = this.b;
                Map mapE = zt.e();
                if (mapE != null) {
                    return mapE.entrySet().remove(obj);
                }
                if (obj instanceof Map.Entry) {
                    Map.Entry entry = (Map.Entry) obj;
                    if (!zt.g()) {
                        int iH = zt.h();
                        Object key = entry.getKey();
                        Object value = entry.getValue();
                        Object obj2 = zt.a;
                        Objects.requireNonNull(obj2);
                        int iM = AbstractC1981ds.m(key, value, iH, obj2, zt.a(), zt.b(), zt.d());
                        if (iM != -1) {
                            zt.f(iM, iH);
                            zt.f--;
                            zt.e += 32;
                            return true;
                        }
                    }
                }
                return false;
            default:
                Zt zt2 = this.b;
                Map mapE2 = zt2.e();
                return mapE2 != null ? mapE2.keySet().remove(obj) : zt2.l(obj) != Zt.j;
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        switch (this.a) {
        }
        return this.b.size();
    }
}
