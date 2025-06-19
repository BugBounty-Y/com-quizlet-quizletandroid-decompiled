package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* loaded from: classes2.dex */
public final class M0 implements com.google.firebase.encoders.c {
    public static final M0 a = new M0();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("logEventKey", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("eventCount", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("inferenceDurationStats", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(3))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        X x = (X) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, x.a);
        dVar.g(c, x.b);
        dVar.g(d, x.c);
    }
}
