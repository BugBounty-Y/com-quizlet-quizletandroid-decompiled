package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_barcode.K7;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class q7 implements n7 {
    public final com.google.firebase.components.l a;
    public final m7 b;

    public q7(Context context, m7 m7Var) {
        this.b = m7Var;
        com.google.android.datatransport.cct.a aVar = com.google.android.datatransport.cct.a.e;
        com.google.android.datatransport.runtime.q.b(context);
        com.google.android.datatransport.runtime.o oVarC = com.google.android.datatransport.runtime.q.a().c(aVar);
        if (com.google.android.datatransport.cct.a.d.contains(new com.google.android.datatransport.c("json"))) {
            new com.google.firebase.components.l(new K7(oVarC, 6));
        }
        this.a = new com.google.firebase.components.l(new K7(oVarC, 7));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.n7
    public final void a(com.quizlet.data.repository.widget.b bVar) {
        m7 m7Var = this.b;
        m7Var.getClass();
        com.google.android.datatransport.runtime.p pVar = (com.google.android.datatransport.runtime.p) this.a.get();
        m7Var.getClass();
        ((com.google.android.gms.internal.ads.C3) bVar.c).i = false;
        com.google.android.gms.internal.ads.C3 c3 = (com.google.android.gms.internal.ads.C3) bVar.c;
        c3.g = Boolean.FALSE;
        R6 r6 = new R6(c3);
        com.quizlet.data.interactor.folderwithcreator.m mVar = (com.quizlet.data.interactor.folderwithcreator.m) bVar.b;
        mVar.a = r6;
        try {
            s7.b();
            s7 s7Var = s7.c;
            C3618f5 c3618f5 = new C3618f5(mVar);
            com.quizlet.data.repository.folderwithcreator.e eVar = new com.quizlet.data.repository.folderwithcreator.e(7);
            s7Var.a(eVar);
            pVar.a(new com.google.android.datatransport.a(new com.quizlet.data.repository.login.a(new HashMap((HashMap) eVar.b), new HashMap((HashMap) eVar.c), (C3676n) eVar.d).n(c3618f5), com.google.android.datatransport.d.b, null), new com.facebook.appevents.k(16));
        } catch (UnsupportedEncodingException e) {
            throw new UnsupportedOperationException("Failed to covert logging to UTF-8 byte array", e);
        }
    }
}
