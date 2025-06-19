package com.google.android.gms.internal.ads;

import android.graphics.Rect;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final /* synthetic */ class Lj implements E5 {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC2529qe b;

    public /* synthetic */ Lj(InterfaceC2529qe interfaceC2529qe, int i) {
        this.a = i;
        this.b = interfaceC2529qe;
    }

    @Override // com.google.android.gms.internal.ads.E5
    public final void R0(D5 d5) {
        switch (this.a) {
            case 0:
                C1669Be c1669BeL = this.b.L();
                Rect rect = d5.d;
                c1669BeL.a0(rect.left, rect.top);
                break;
            case 1:
                HashMap map = new HashMap();
                map.put("isVisible", true != d5.j ? "0" : "1");
                this.b.j("onAdVisibilityChanged", map);
                break;
            default:
                C1669Be c1669BeL2 = this.b.L();
                Rect rect2 = d5.d;
                c1669BeL2.a0(rect2.left, rect2.top);
                break;
        }
    }
}
