package com.google.firebase.sessions;

import android.os.Build;

/* renamed from: com.google.firebase.sessions.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3981c implements com.google.firebase.encoders.c {
    public static final C3981c a = new C3981c();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("packageName");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("versionName");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("appBuildVersion");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("deviceManufacturer");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("currentProcessDetails");
    public static final com.google.firebase.encoders.b g = com.google.firebase.encoders.b.b("appProcessDetails");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        C3979a c3979a = (C3979a) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, c3979a.a);
        dVar.g(c, c3979a.b);
        dVar.g(d, c3979a.c);
        dVar.g(e, Build.MANUFACTURER);
        dVar.g(f, c3979a.d);
        dVar.g(g, c3979a.e);
    }
}
