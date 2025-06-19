package com.google.firebase.sessions;

import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;

/* renamed from: com.google.firebase.sessions.h, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3986h implements com.google.firebase.encoders.c {
    public static final C3986h a = new C3986h();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b(DBAnswerFields.Names.SESSION_ID);
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("firstSessionId");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("sessionIndex");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("eventTimestampUs");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("dataCollectionStatus");
    public static final com.google.firebase.encoders.b g = com.google.firebase.encoders.b.b("firebaseInstallationId");
    public static final com.google.firebase.encoders.b h = com.google.firebase.encoders.b.b("firebaseAuthenticationToken");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        Y y = (Y) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, y.a);
        dVar.g(c, y.b);
        dVar.c(d, y.c);
        dVar.b(e, y.d);
        dVar.g(f, y.e);
        dVar.g(g, y.f);
        dVar.g(h, y.g);
    }
}
