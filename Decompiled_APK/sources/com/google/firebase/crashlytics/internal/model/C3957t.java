package com.google.firebase.crashlytics.internal.model;

import com.quizlet.db.data.models.persisted.fields.DBUserFields;

/* renamed from: com.google.firebase.crashlytics.internal.model.t, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3957t implements com.google.firebase.encoders.c {
    public static final C3957t a = new C3957t();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("timestamp");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b(DBUserFields.Names.USER_UPGRADE_TYPE);
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("app");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("device");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("log");
    public static final com.google.firebase.encoders.b g = com.google.firebase.encoders.b.b("rollouts");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        P p = (P) ((K0) obj);
        dVar.b(b, p.a);
        dVar.g(c, p.b);
        dVar.g(d, p.c);
        dVar.g(e, p.d);
        dVar.g(f, p.e);
        dVar.g(g, p.f);
    }
}
