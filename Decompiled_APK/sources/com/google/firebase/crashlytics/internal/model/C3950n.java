package com.google.firebase.crashlytics.internal.model;

import com.quizlet.db.data.models.persisted.fields.DBUserFields;

/* renamed from: com.google.firebase.crashlytics.internal.model.n, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3950n implements com.google.firebase.encoders.c {
    public static final C3950n a = new C3950n();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b(DBUserFields.Names.USER_UPGRADE_TYPE);
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("reason");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("frames");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("causedBy");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("overflowCount");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        U u = (U) ((y0) obj);
        dVar.g(b, u.a);
        dVar.g(c, u.b);
        dVar.g(d, u.c);
        dVar.g(e, u.d);
        dVar.c(f, u.e);
    }
}
