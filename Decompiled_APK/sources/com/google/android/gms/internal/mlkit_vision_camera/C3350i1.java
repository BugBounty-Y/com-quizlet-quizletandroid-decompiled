package com.google.android.gms.internal.mlkit_vision_camera;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.i1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3350i1 implements com.google.firebase.encoders.c {
    public static final C3350i1 a = new C3350i1();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("appId", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("appVersion", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("firebaseProjectId", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("mlSdkVersion", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(4))));
    public static final com.google.firebase.encoders.b f = new com.google.firebase.encoders.b("tfliteSchemaVersion", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(5))));
    public static final com.google.firebase.encoders.b g = new com.google.firebase.encoders.b("gcmSenderId", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(6))));
    public static final com.google.firebase.encoders.b h = new com.google.firebase.encoders.b(DTBMetricsConfiguration.APSMETRICS_APIKEY, assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(7))));
    public static final com.google.firebase.encoders.b i = new com.google.firebase.encoders.b("languages", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(8))));
    public static final com.google.firebase.encoders.b j = new com.google.firebase.encoders.b("mlSdkInstanceId", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(9))));
    public static final com.google.firebase.encoders.b k = new com.google.firebase.encoders.b("isClearcutClient", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(10))));
    public static final com.google.firebase.encoders.b l = new com.google.firebase.encoders.b("isStandaloneMlkit", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(11))));
    public static final com.google.firebase.encoders.b m = new com.google.firebase.encoders.b("isJsonLogging", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(12))));
    public static final com.google.firebase.encoders.b n = new com.google.firebase.encoders.b("buildLevel", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(13))));
    public static final com.google.firebase.encoders.b o = new com.google.firebase.encoders.b("optionalModuleVersion", assistantMode.refactored.a.o(AbstractC1642h.o(B1.class, new C3316a(14))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        I2 i2 = (I2) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, i2.a);
        dVar.g(c, i2.b);
        dVar.g(d, null);
        dVar.g(e, i2.c);
        dVar.g(f, i2.d);
        dVar.g(g, null);
        dVar.g(h, null);
        dVar.g(i, i2.e);
        dVar.g(j, i2.f);
        dVar.g(k, i2.g);
        dVar.g(l, i2.h);
        dVar.g(m, i2.i);
        dVar.g(n, i2.j);
        dVar.g(o, i2.k);
    }
}
