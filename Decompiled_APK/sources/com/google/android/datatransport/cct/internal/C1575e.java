package com.google.android.datatransport.cct.internal;

/* renamed from: com.google.android.datatransport.cct.internal.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1575e implements com.google.firebase.encoders.c {
    public static final C1575e a = new C1575e();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("privacyContext");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("productIdOrigin");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, ((o) ((B) obj)).a);
        dVar.g(c, A.a);
    }
}
