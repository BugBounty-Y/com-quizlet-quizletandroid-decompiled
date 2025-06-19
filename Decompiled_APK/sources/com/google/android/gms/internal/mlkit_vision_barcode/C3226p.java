package com.google.android.gms.internal.mlkit_vision_barcode;

import java.util.AbstractSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.p, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3226p extends AbstractSet {
    public final /* synthetic */ int a;
    public final /* synthetic */ r b;

    public /* synthetic */ C3226p(r rVar, int i) {
        this.a = i;
        this.b = rVar;
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
                r rVar = this.b;
                Map mapE = rVar.e();
                if (mapE != null) {
                    return mapE.entrySet().contains(obj);
                }
                if (obj instanceof Map.Entry) {
                    Map.Entry entry = (Map.Entry) obj;
                    int iJ = rVar.j(entry.getKey());
                    if (iJ != -1 && com.google.android.gms.internal.mlkit_vision_common.H3.b(rVar.d()[iJ], entry.getValue())) {
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
                r rVar = this.b;
                Map mapE = rVar.e();
                return mapE != null ? mapE.entrySet().iterator() : new C3208n(rVar, 1);
            default:
                r rVar2 = this.b;
                Map mapE2 = rVar2.e();
                return mapE2 != null ? mapE2.keySet().iterator() : new C3208n(rVar2, 0);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean remove(Object obj) {
        switch (this.a) {
            case 0:
                r rVar = this.b;
                Map mapE = rVar.e();
                if (mapE != null) {
                    return mapE.entrySet().remove(obj);
                }
                if (obj instanceof Map.Entry) {
                    Map.Entry entry = (Map.Entry) obj;
                    if (!rVar.g()) {
                        int iH = rVar.h();
                        Object key = entry.getKey();
                        Object value = entry.getValue();
                        Object obj2 = rVar.a;
                        Objects.requireNonNull(obj2);
                        int iD = com.google.android.gms.internal.mlkit_vision_common.K3.d(key, value, iH, obj2, rVar.a(), rVar.b(), rVar.d());
                        if (iD != -1) {
                            rVar.f(iD, iH);
                            rVar.f--;
                            rVar.e += 32;
                            return true;
                        }
                    }
                }
                return false;
            default:
                r rVar2 = this.b;
                Map mapE2 = rVar2.e();
                return mapE2 != null ? mapE2.keySet().remove(obj) : rVar2.l(obj) != r.j;
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        switch (this.a) {
        }
        return this.b.size();
    }
}
