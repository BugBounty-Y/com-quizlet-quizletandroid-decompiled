package com.google.firebase.messaging;

/* renamed from: com.google.firebase.messaging.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3964a implements com.google.firebase.encoders.c {
    public static final C3964a a = new C3964a();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("projectNumber", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("messageId", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("instanceId", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("messageType", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(4))));
    public static final com.google.firebase.encoders.b f = new com.google.firebase.encoders.b("sdkPlatform", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(5))));
    public static final com.google.firebase.encoders.b g = new com.google.firebase.encoders.b("packageName", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(6))));
    public static final com.google.firebase.encoders.b h = new com.google.firebase.encoders.b("collapseKey", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(7))));
    public static final com.google.firebase.encoders.b i = new com.google.firebase.encoders.b("priority", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(8))));
    public static final com.google.firebase.encoders.b j = new com.google.firebase.encoders.b("ttl", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(9))));
    public static final com.google.firebase.encoders.b k = new com.google.firebase.encoders.b("topic", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(10))));
    public static final com.google.firebase.encoders.b l = new com.google.firebase.encoders.b("bulkId", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(11))));
    public static final com.google.firebase.encoders.b m = new com.google.firebase.encoders.b("event", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(12))));
    public static final com.google.firebase.encoders.b n = new com.google.firebase.encoders.b("analyticsLabel", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(13))));
    public static final com.google.firebase.encoders.b o = new com.google.firebase.encoders.b("campaignId", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(14))));
    public static final com.google.firebase.encoders.b p = new com.google.firebase.encoders.b("composerLabel", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(15))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.messaging.reporting.d dVar = (com.google.firebase.messaging.reporting.d) obj;
        com.google.firebase.encoders.d dVar2 = (com.google.firebase.encoders.d) obj2;
        dVar2.b(b, dVar.a);
        dVar2.g(c, dVar.b);
        dVar2.g(d, dVar.c);
        dVar2.g(e, dVar.d);
        dVar2.g(f, com.google.firebase.messaging.reporting.c.ANDROID);
        dVar2.g(g, dVar.e);
        dVar2.g(h, dVar.f);
        dVar2.c(i, dVar.g);
        dVar2.c(j, dVar.h);
        dVar2.g(k, dVar.i);
        dVar2.b(l, 0L);
        dVar2.g(m, com.google.firebase.messaging.reporting.a.MESSAGE_DELIVERED);
        dVar2.g(n, dVar.j);
        dVar2.b(o, 0L);
        dVar2.g(p, dVar.k);
    }
}
