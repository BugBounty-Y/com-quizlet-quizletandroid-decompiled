package com.google.android.gms.internal.mlkit_vision_common;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.n2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3500n2 implements com.google.firebase.encoders.c {
    public static final C3500n2 a = new C3500n2();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("appId", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("appVersion", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("firebaseProjectId", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("mlSdkVersion", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(4))));
    public static final com.google.firebase.encoders.b f = new com.google.firebase.encoders.b("tfliteSchemaVersion", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(5))));
    public static final com.google.firebase.encoders.b g = new com.google.firebase.encoders.b("gcmSenderId", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(6))));
    public static final com.google.firebase.encoders.b h = new com.google.firebase.encoders.b(DTBMetricsConfiguration.APSMETRICS_APIKEY, assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(7))));
    public static final com.google.firebase.encoders.b i = new com.google.firebase.encoders.b("languages", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(8))));
    public static final com.google.firebase.encoders.b j = new com.google.firebase.encoders.b("mlSdkInstanceId", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(9))));
    public static final com.google.firebase.encoders.b k = new com.google.firebase.encoders.b("isClearcutClient", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(10))));
    public static final com.google.firebase.encoders.b l = new com.google.firebase.encoders.b("isStandaloneMlkit", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(11))));
    public static final com.google.firebase.encoders.b m = new com.google.firebase.encoders.b("isJsonLogging", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(12))));
    public static final com.google.firebase.encoders.b n = new com.google.firebase.encoders.b("buildLevel", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(13))));
    public static final com.google.firebase.encoders.b o = new com.google.firebase.encoders.b("optionalModuleVersion", assistantMode.refactored.a.o(AbstractC1642h.p(InterfaceC3437d.class, new C3419a(14))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        C3484k4 c3484k4 = (C3484k4) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, c3484k4.a);
        dVar.g(c, c3484k4.b);
        dVar.g(d, null);
        dVar.g(e, c3484k4.c);
        dVar.g(f, c3484k4.d);
        dVar.g(g, null);
        dVar.g(h, null);
        dVar.g(i, c3484k4.e);
        dVar.g(j, c3484k4.f);
        dVar.g(k, c3484k4.g);
        dVar.g(l, c3484k4.h);
        dVar.g(m, c3484k4.i);
        dVar.g(n, c3484k4.j);
        dVar.g(o, c3484k4.k);
    }
}
