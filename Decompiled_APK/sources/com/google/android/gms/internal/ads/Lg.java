package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class Lg implements InterfaceC2617sh, InterfaceC2231jh {
    public final Vp a;

    public Lg(Vp vp) {
        this.a = vp;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2231jh
    public final void E(Context context) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2231jh
    public final void j(Context context) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2231jh
    public final void o(Context context) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    public final void s() {
        androidx.core.os.b bVar = this.a.d0;
        if (bVar == null || !bVar.a) {
            return;
        }
        ArrayList arrayList = new ArrayList();
        String str = (String) bVar.c;
        if (str.isEmpty()) {
            return;
        }
        arrayList.add(str);
    }
}
