package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.qa, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2525qa implements Fv {
    public final /* synthetic */ int a;
    public final com.google.common.util.concurrent.e b;

    public /* synthetic */ C2525qa(int i, com.google.common.util.concurrent.e eVar) {
        this.a = i;
        this.b = eVar;
    }

    @Override // com.google.android.gms.internal.ads.Fv
    public final com.google.common.util.concurrent.e b(Object obj) {
        switch (this.a) {
            case 0:
                return AbstractC2025es.N(this.b, new C2439oa(1, this, obj), AbstractC2270kd.g);
            default:
                return this.b;
        }
    }
}
