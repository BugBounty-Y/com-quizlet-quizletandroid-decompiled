package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.m2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3202m2 implements com.google.firebase.encoders.c {
    public static final C3202m2 a = new C3202m2();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("durationMs", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("errorCode", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("isColdCall", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("autoManageModelOnBackground", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(4))));
    public static final com.google.firebase.encoders.b f = new com.google.firebase.encoders.b("autoManageModelOnLowMemory", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(5))));
    public static final com.google.firebase.encoders.b g = new com.google.firebase.encoders.b("isNnApiEnabled", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(6))));
    public static final com.google.firebase.encoders.b h = new com.google.firebase.encoders.b("eventsCount", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(7))));
    public static final com.google.firebase.encoders.b i = new com.google.firebase.encoders.b("otherErrors", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(8))));
    public static final com.google.firebase.encoders.b j = new com.google.firebase.encoders.b("remoteConfigValueForAcceleration", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(9))));
    public static final com.google.firebase.encoders.b k = new com.google.firebase.encoders.b("isAccelerated", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(10))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        C3196l5 c3196l5 = (C3196l5) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, c3196l5.a);
        dVar.g(c, c3196l5.b);
        dVar.g(d, c3196l5.c);
        dVar.g(e, c3196l5.d);
        dVar.g(f, c3196l5.e);
        dVar.g(g, null);
        dVar.g(h, null);
        dVar.g(i, null);
        dVar.g(j, null);
        dVar.g(k, null);
    }
}
