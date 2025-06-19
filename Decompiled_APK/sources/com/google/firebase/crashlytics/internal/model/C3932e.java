package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3932e implements com.google.firebase.encoders.c {
    public static final C3932e a = new C3932e();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("files");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("orgId");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        G g = (G) ((t0) obj);
        dVar.g(b, g.a);
        dVar.g(c, g.b);
    }
}
