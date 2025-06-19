package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.g4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3150g4 implements com.google.firebase.encoders.c {
    public static final C3150g4 a = new C3150g4();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("appName", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b(DBAnswerFields.Names.SESSION_ID, assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("startZoomLevel", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("endZoomLevel", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(4))));
    public static final com.google.firebase.encoders.b f = new com.google.firebase.encoders.b("durationMs", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(5))));
    public static final com.google.firebase.encoders.b g = new com.google.firebase.encoders.b("predictedArea", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(6))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        ((AbstractC3126d7) obj).getClass();
        dVar.g(b, null);
        dVar.g(c, null);
        dVar.g(d, null);
        dVar.g(e, null);
        dVar.g(f, null);
        dVar.g(g, null);
    }
}
