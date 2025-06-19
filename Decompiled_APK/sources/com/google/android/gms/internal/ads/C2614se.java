package com.google.android.gms.internal.ads;

import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.se, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2614se implements com.google.android.gms.ads.internal.overlay.j {
    public final C2743ve a;
    public final com.google.android.gms.ads.internal.overlay.j b;

    public C2614se(C2743ve c2743ve, com.google.android.gms.ads.internal.overlay.j jVar) {
        this.a = c2743ve;
        this.b = jVar;
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void I3() {
        com.google.android.gms.ads.internal.overlay.j jVar = this.b;
        if (jVar != null) {
            jVar.I3();
        }
        this.a.e0();
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void L2() {
        com.google.android.gms.ads.internal.overlay.j jVar = this.b;
        if (jVar != null) {
            jVar.L2();
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void X(int i) {
        com.google.android.gms.ads.internal.overlay.j jVar = this.b;
        if (jVar != null) {
            jVar.X(i);
        }
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = this.a.a;
        AbstractC2096gb.h((B7) viewTreeObserverOnGlobalLayoutListenerC2829xe.L.c, viewTreeObserverOnGlobalLayoutListenerC2829xe.J, "aeh2");
        HashMap map = new HashMap(1);
        map.put("version", viewTreeObserverOnGlobalLayoutListenerC2829xe.e.a);
        viewTreeObserverOnGlobalLayoutListenerC2829xe.j("onhide", map);
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void Y3() {
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void f3() {
        com.google.android.gms.ads.internal.overlay.j jVar = this.b;
        if (jVar != null) {
            jVar.f3();
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void v3() {
    }
}
