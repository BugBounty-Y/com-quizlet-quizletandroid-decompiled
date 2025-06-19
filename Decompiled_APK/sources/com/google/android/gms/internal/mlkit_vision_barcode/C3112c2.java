package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.c2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3112c2 implements com.google.firebase.encoders.c {
    public static final C3112c2 a = new C3112c2();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("maxMs", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("minMs", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("avgMs", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("firstQuartileMs", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(4))));
    public static final com.google.firebase.encoders.b f = new com.google.firebase.encoders.b("medianMs", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(5))));
    public static final com.google.firebase.encoders.b g = new com.google.firebase.encoders.b("thirdQuartileMs", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(6))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        C3115c5 c3115c5 = (C3115c5) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, c3115c5.a);
        dVar.g(c, c3115c5.b);
        dVar.g(d, c3115c5.c);
        dVar.g(e, c3115c5.d);
        dVar.g(f, c3115c5.e);
        dVar.g(g, c3115c5.f);
    }
}
