package com.google.android.gms.internal.mlkit_vision_document_scanner;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* loaded from: classes2.dex */
public final class U3 implements com.google.firebase.encoders.c {
    public static final U3 a = new U3();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("appId", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("appVersion", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("firebaseProjectId", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("mlSdkVersion", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(4))));
    public static final com.google.firebase.encoders.b f = new com.google.firebase.encoders.b("tfliteSchemaVersion", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(5))));
    public static final com.google.firebase.encoders.b g = new com.google.firebase.encoders.b("gcmSenderId", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(6))));
    public static final com.google.firebase.encoders.b h = new com.google.firebase.encoders.b(DTBMetricsConfiguration.APSMETRICS_APIKEY, assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(7))));
    public static final com.google.firebase.encoders.b i = new com.google.firebase.encoders.b("languages", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(8))));
    public static final com.google.firebase.encoders.b j = new com.google.firebase.encoders.b("mlSdkInstanceId", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(9))));
    public static final com.google.firebase.encoders.b k = new com.google.firebase.encoders.b("isClearcutClient", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(10))));
    public static final com.google.firebase.encoders.b l = new com.google.firebase.encoders.b("isStandaloneMlkit", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(11))));
    public static final com.google.firebase.encoders.b m = new com.google.firebase.encoders.b("isJsonLogging", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(12))));
    public static final com.google.firebase.encoders.b n = new com.google.firebase.encoders.b("buildLevel", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(13))));
    public static final com.google.firebase.encoders.b o = new com.google.firebase.encoders.b("optionalModuleVersion", assistantMode.refactored.a.o(AbstractC1642h.q(InterfaceC3668m.class, new C3644j(14))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        R6 r6 = (R6) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, r6.a);
        dVar.g(c, r6.b);
        dVar.g(d, null);
        dVar.g(e, r6.c);
        dVar.g(f, r6.d);
        dVar.g(g, null);
        dVar.g(h, null);
        dVar.g(i, r6.e);
        dVar.g(j, r6.f);
        dVar.g(k, r6.g);
        dVar.g(l, r6.h);
        dVar.g(m, r6.i);
        dVar.g(n, r6.j);
        dVar.g(o, r6.k);
    }
}
