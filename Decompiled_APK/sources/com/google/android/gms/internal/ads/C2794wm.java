package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.wm, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2794wm implements InterfaceC2751vm {
    public final InterfaceC2751vm a;
    public final InterfaceC2544qt b;

    public C2794wm(InterfaceC2751vm interfaceC2751vm, InterfaceC2544qt interfaceC2544qt) {
        this.a = interfaceC2751vm;
        this.b = interfaceC2544qt;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final boolean a(C1849aq c1849aq, Vp vp) {
        return this.a.a(c1849aq, vp);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final com.google.common.util.concurrent.e b(C1849aq c1849aq, Vp vp) {
        return AbstractC2025es.L(this.a.b(c1849aq, vp), this.b, AbstractC2270kd.a);
    }
}
