package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* loaded from: classes2.dex */
public final class H2 implements com.google.firebase.encoders.c {
    public static final H2 a = new H2();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("inferenceCommonLogEvent", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("options", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("detectedBarcodeFormats", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("detectedBarcodeValueTypes", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(4))));
    public static final com.google.firebase.encoders.b f = new com.google.firebase.encoders.b("imageInfo", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(5))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        I5 i5 = (I5) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, i5.a);
        dVar.g(c, i5.b);
        dVar.g(d, i5.c);
        dVar.g(e, i5.d);
        dVar.g(f, i5.e);
    }
}
