package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* loaded from: classes2.dex */
public final class N0 implements com.google.firebase.encoders.c {
    public static final N0 a = new N0();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("errorCode", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("hasResult", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("isColdCall", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("imageInfo", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(4))));
    public static final com.google.firebase.encoders.b f = new com.google.firebase.encoders.b("options", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(5))));
    public static final com.google.firebase.encoders.b g = new com.google.firebase.encoders.b("detectedBarcodeFormats", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(6))));
    public static final com.google.firebase.encoders.b h = new com.google.firebase.encoders.b("detectedBarcodeValueTypes", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(7))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        W w = (W) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, w.a);
        dVar.g(c, null);
        dVar.g(d, w.b);
        dVar.g(e, null);
        dVar.g(f, w.c);
        dVar.g(g, w.d);
        dVar.g(h, w.e);
    }
}
