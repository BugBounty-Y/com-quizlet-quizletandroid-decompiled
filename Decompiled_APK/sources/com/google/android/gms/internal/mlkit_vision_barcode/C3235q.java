package com.google.android.gms.internal.mlkit_vision_barcode;

import java.util.Map;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.q, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3235q extends AbstractC3181k {
    public final Object a;
    public int b;
    public final /* synthetic */ r c;

    public C3235q(r rVar, int i) {
        this.c = rVar;
        Object obj = r.j;
        this.a = rVar.b()[i];
        this.b = i;
    }

    public final void a() {
        int i = this.b;
        Object obj = this.a;
        r rVar = this.c;
        if (i != -1 && i < rVar.size()) {
            if (com.google.android.gms.internal.mlkit_vision_common.H3.b(obj, rVar.b()[this.b])) {
                return;
            }
        }
        Object obj2 = r.j;
        this.b = rVar.j(obj);
    }

    @Override // java.util.Map.Entry
    public final Object getKey() {
        return this.a;
    }

    @Override // java.util.Map.Entry
    public final Object getValue() {
        r rVar = this.c;
        Map mapE = rVar.e();
        if (mapE != null) {
            return mapE.get(this.a);
        }
        a();
        int i = this.b;
        if (i == -1) {
            return null;
        }
        return rVar.d()[i];
    }

    @Override // java.util.Map.Entry
    public final Object setValue(Object obj) {
        r rVar = this.c;
        Map mapE = rVar.e();
        Object obj2 = this.a;
        if (mapE != null) {
            return mapE.put(obj2, obj);
        }
        a();
        int i = this.b;
        if (i == -1) {
            rVar.put(obj2, obj);
            return null;
        }
        Object obj3 = rVar.d()[i];
        rVar.d()[this.b] = obj;
        return obj3;
    }
}
