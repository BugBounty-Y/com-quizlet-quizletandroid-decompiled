package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.internal.ads.Xt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.n, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3208n extends Xt {
    public final /* synthetic */ int f;
    public final /* synthetic */ r g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C3208n(r rVar, int i) {
        super(rVar);
        this.f = i;
        this.g = rVar;
    }

    @Override // com.google.android.gms.internal.ads.Xt
    public final Object a(int i) {
        r rVar = this.g;
        switch (this.f) {
            case 0:
                Object obj = r.j;
                return rVar.b()[i];
            case 1:
                return new C3235q(rVar, i);
            default:
                Object obj2 = r.j;
                return rVar.d()[i];
        }
    }
}
