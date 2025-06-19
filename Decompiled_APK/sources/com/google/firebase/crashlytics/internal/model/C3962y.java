package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.y, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3962y implements com.google.firebase.encoders.c {
    public static final C3962y a = new C3962y();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("platform");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("version");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("buildVersion");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("jailbroken");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        C3943j0 c3943j0 = (C3943j0) ((L0) obj);
        dVar.c(b, c3943j0.a);
        dVar.g(c, c3943j0.b);
        dVar.g(d, c3943j0.c);
        dVar.a(e, c3943j0.d);
    }
}
