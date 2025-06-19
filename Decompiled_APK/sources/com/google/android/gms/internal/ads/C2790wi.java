package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.wi, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2790wi implements CC {
    public final /* synthetic */ int a;
    public final Fi b;

    public /* synthetic */ C2790wi(Fi fi, int i) {
        this.a = i;
        this.b = fi;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.b.c;
                if (interfaceC2529qe == null) {
                    return null;
                }
                return interfaceC2529qe.n();
            case 1:
                InterfaceC2529qe interfaceC2529qe2 = (InterfaceC2529qe) this.b.c;
                if (interfaceC2529qe2 != null) {
                    return interfaceC2529qe2.n();
                }
                return null;
            default:
                return (InterfaceC2529qe) this.b.c;
        }
    }
}
