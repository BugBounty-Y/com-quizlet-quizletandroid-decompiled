package com.google.android.gms.internal.mlkit_vision_barcode;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.p4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3231p4 implements com.google.firebase.encoders.c {
    public static final C3231p4 a = new C3231p4();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("appId", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("appVersion", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("firebaseProjectId", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("mlSdkVersion", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(4))));
    public static final com.google.firebase.encoders.b f = new com.google.firebase.encoders.b("tfliteSchemaVersion", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(5))));
    public static final com.google.firebase.encoders.b g = new com.google.firebase.encoders.b("gcmSenderId", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(6))));
    public static final com.google.firebase.encoders.b h = new com.google.firebase.encoders.b(DTBMetricsConfiguration.APSMETRICS_APIKEY, assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(7))));
    public static final com.google.firebase.encoders.b i = new com.google.firebase.encoders.b("languages", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(8))));
    public static final com.google.firebase.encoders.b j = new com.google.firebase.encoders.b("mlSdkInstanceId", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(9))));
    public static final com.google.firebase.encoders.b k = new com.google.firebase.encoders.b("isClearcutClient", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(10))));
    public static final com.google.firebase.encoders.b l = new com.google.firebase.encoders.b("isStandaloneMlkit", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(11))));
    public static final com.google.firebase.encoders.b m = new com.google.firebase.encoders.b("isJsonLogging", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(12))));
    public static final com.google.firebase.encoders.b n = new com.google.firebase.encoders.b("buildLevel", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(13))));
    public static final com.google.firebase.encoders.b o = new com.google.firebase.encoders.b("optionalModuleVersion", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(14))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        C3198l7 c3198l7 = (C3198l7) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, c3198l7.a);
        dVar.g(c, c3198l7.b);
        dVar.g(d, null);
        dVar.g(e, c3198l7.c);
        dVar.g(f, c3198l7.d);
        dVar.g(g, null);
        dVar.g(h, null);
        dVar.g(i, c3198l7.e);
        dVar.g(j, c3198l7.f);
        dVar.g(k, c3198l7.g);
        dVar.g(l, c3198l7.h);
        dVar.g(m, c3198l7.i);
        dVar.g(n, c3198l7.j);
        dVar.g(o, c3198l7.k);
    }
}
