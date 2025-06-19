package com.google.android.gms.internal.ads;

import android.view.ViewParent;

/* renamed from: com.google.android.gms.internal.ads.bg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1883bg implements InterfaceC2189ih {
    public final InterfaceC2529qe a;
    public final Hk b;
    public final Vp c;

    public C1883bg(InterfaceC2529qe interfaceC2529qe, Hk hk, Vp vp) {
        this.a = interfaceC2529qe;
        this.b = hk;
        this.c = vp;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
    public final void K() {
        InterfaceC2529qe interfaceC2529qe;
        String str;
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Pc)).booleanValue() || (interfaceC2529qe = this.a) == null) {
            return;
        }
        ViewParent parent = interfaceC2529qe.N().getParent();
        while (true) {
            if (parent == null) {
                str = "0";
                break;
            } else {
                if (parent.getClass().getName().startsWith("androidx.compose.ui")) {
                    str = "1";
                    break;
                }
                parent = parent.getParent();
            }
        }
        Fi fiA = this.b.a();
        fiA.o("action", "hcp");
        fiA.o("hcp", str);
        fiA.p(this.c);
        fiA.x();
    }
}
