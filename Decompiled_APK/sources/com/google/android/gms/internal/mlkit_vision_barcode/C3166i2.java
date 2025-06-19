package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.i2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3166i2 implements com.google.firebase.encoders.c {
    public static final C3166i2 a = new C3166i2();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("imageFormat", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("originalImageSize", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("compressedImageSize", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("isOdmlImage", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(4))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        C3160h5 c3160h5 = (C3160h5) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, c3160h5.a);
        dVar.g(c, c3160h5.b);
        dVar.g(d, null);
        dVar.g(e, null);
    }
}
