package com.google.android.gms.internal.mlkit_vision_camera;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* loaded from: classes2.dex */
public final class H implements com.google.firebase.encoders.c {
    public static final H a = new H();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("cameraSource", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("eventType", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("requestedPreviewHeight", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("requestedPreviewWidth", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(4))));
    public static final com.google.firebase.encoders.b f = new com.google.firebase.encoders.b("actualPreviewHeight", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(5))));
    public static final com.google.firebase.encoders.b g = new com.google.firebase.encoders.b("actualPreviewWidth", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(6))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        C3393t1 c3393t1 = (C3393t1) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, c3393t1.a);
        dVar.g(c, c3393t1.b);
        dVar.g(d, c3393t1.c);
        dVar.g(e, c3393t1.d);
        dVar.g(f, c3393t1.e);
        dVar.g(g, c3393t1.f);
    }
}
