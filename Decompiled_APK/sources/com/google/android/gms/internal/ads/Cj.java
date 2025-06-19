package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final /* synthetic */ class Cj implements Fv {
    public final /* synthetic */ int a;
    public final /* synthetic */ C2846xv b;

    public /* synthetic */ Cj(C2846xv c2846xv, int i) {
        this.a = i;
        this.b = c2846xv;
    }

    @Override // com.google.android.gms.internal.ads.Fv
    public final com.google.common.util.concurrent.e b(Object obj) throws zzegy {
        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
        switch (this.a) {
            case 0:
                if (interfaceC2529qe != null) {
                    return this.b;
                }
                throw new zzegy(1, "Retrieve Web View from image ad response failed.");
            default:
                if (interfaceC2529qe == null || interfaceC2529qe.p() == null) {
                    throw new zzegy(1, "Retrieve video view in html5 ad response failed.");
                }
                return this.b;
        }
    }
}
