package com.google.android.gms.internal.mlkit_vision_document_scanner;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* loaded from: classes2.dex */
public final class J2 implements com.google.firebase.encoders.c {
    public static final J2 a = new J2();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("durationMs", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("errorCode", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("options", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("pageCount", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(4))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        L5 l5 = (L5) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, l5.a);
        dVar.g(c, l5.b);
        dVar.g(d, l5.c);
        dVar.g(e, l5.d);
    }
}
