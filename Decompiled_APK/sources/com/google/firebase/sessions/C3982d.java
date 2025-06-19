package com.google.firebase.sessions;

import android.os.Build;
import com.amazon.device.ads.DtbDeviceData;

/* renamed from: com.google.firebase.sessions.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3982d implements com.google.firebase.encoders.c {
    public static final C3982d a = new C3982d();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("appId");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("deviceModel");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("sessionSdkVersion");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b(DtbDeviceData.DEVICE_DATA_OS_VERSION_KEY);
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("logEnvironment");
    public static final com.google.firebase.encoders.b g = com.google.firebase.encoders.b.b("androidAppInfo");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        C3980b c3980b = (C3980b) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, c3980b.a);
        dVar.g(c, Build.MODEL);
        dVar.g(d, "2.1.1");
        dVar.g(e, Build.VERSION.RELEASE);
        dVar.g(f, C.LOG_ENVIRONMENT_PROD);
        dVar.g(g, c3980b.b);
    }
}
