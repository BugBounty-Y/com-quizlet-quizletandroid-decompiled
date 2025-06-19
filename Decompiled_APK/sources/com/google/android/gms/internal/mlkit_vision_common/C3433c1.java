package com.google.android.gms.internal.mlkit_vision_common;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.c1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3433c1 implements com.google.firebase.encoders.c {
    public static final C3433c1 a = new C3433c1();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("durationMs", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("imageSource", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("imageFormat", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("imageByteSize", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(4))));
    public static final com.google.firebase.encoders.b f = new com.google.firebase.encoders.b("imageWidth", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(5))));
    public static final com.google.firebase.encoders.b g = new com.google.firebase.encoders.b("imageHeight", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(6))));
    public static final com.google.firebase.encoders.b h = new com.google.firebase.encoders.b("rotationDegrees", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(7))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        C3453f3 c3453f3 = (C3453f3) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, c3453f3.a);
        dVar.g(c, c3453f3.b);
        dVar.g(d, c3453f3.c);
        dVar.g(e, c3453f3.d);
        dVar.g(f, c3453f3.e);
        dVar.g(g, c3453f3.f);
        dVar.g(h, c3453f3.g);
    }
}
