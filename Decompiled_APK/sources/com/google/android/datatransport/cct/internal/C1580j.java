package com.google.android.datatransport.cct.internal;

/* renamed from: com.google.android.datatransport.cct.internal.j, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1580j implements com.google.firebase.encoders.c {
    public static final C1580j a = new C1580j();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("requestTimeMs");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("requestUptimeMs");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("clientInfo");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("logSource");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("logSourceName");
    public static final com.google.firebase.encoders.b g = com.google.firebase.encoders.b.b("logEvent");
    public static final com.google.firebase.encoders.b h = com.google.firebase.encoders.b.b("qosTier");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        u uVar = (u) ((G) obj);
        dVar.b(b, uVar.a);
        dVar.b(c, uVar.b);
        dVar.g(d, uVar.c);
        dVar.g(e, uVar.d);
        dVar.g(f, uVar.e);
        dVar.g(g, uVar.f);
        dVar.g(h, K.a);
    }
}
