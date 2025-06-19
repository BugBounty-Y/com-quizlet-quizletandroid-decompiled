package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.e6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1996e6 implements L5 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C1996e6(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.google.android.gms.internal.ads.L5
    public final void V(boolean z) {
        switch (this.a) {
            case 0:
                C2084g6 c2084g6 = (C2084g6) this.b;
                if (!z) {
                    C2084g6.p(c2084g6);
                    break;
                } else {
                    c2084g6.v();
                    break;
                }
            default:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.w)).booleanValue()) {
                    ((C2928zr) this.b).f(z);
                    break;
                }
                break;
        }
    }
}
