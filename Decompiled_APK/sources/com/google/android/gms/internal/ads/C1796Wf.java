package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.Wf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C1796Wf implements Nh {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C1796Wf(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.google.android.gms.internal.ads.Nh
    public final void a() {
        com.google.android.gms.ads.internal.overlay.d dVarQ;
        switch (this.a) {
            case 0:
                ((Gh) this.b).a();
                break;
            default:
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.b;
                if (interfaceC2529qe != null && (dVarQ = interfaceC2529qe.Q()) != null) {
                    dVarQ.b();
                    break;
                }
                break;
        }
    }
}
