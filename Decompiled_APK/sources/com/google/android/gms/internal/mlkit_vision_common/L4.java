package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_barcode.K7;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class L4 implements I4 {
    public final com.google.firebase.components.l a;
    public final H4 b;

    public L4(Context context, H4 h4) {
        this.b = h4;
        com.google.android.datatransport.cct.a aVar = com.google.android.datatransport.cct.a.e;
        com.google.android.datatransport.runtime.q.b(context);
        com.google.android.datatransport.runtime.o oVarC = com.google.android.datatransport.runtime.q.a().c(aVar);
        if (com.google.android.datatransport.cct.a.d.contains(new com.google.android.datatransport.c("json"))) {
            new com.google.firebase.components.l(new K7(oVarC, 4));
        }
        this.a = new com.google.firebase.components.l(new K7(oVarC, 5));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.I4
    public final void a(com.quizlet.data.repository.qclass.c cVar) {
        H4 h4 = this.b;
        h4.getClass();
        com.google.android.datatransport.runtime.p pVar = (com.google.android.datatransport.runtime.p) this.a.get();
        h4.getClass();
        ((com.google.android.gms.internal.ads.C3) cVar.c).i = false;
        com.google.android.gms.internal.ads.C3 c3 = (com.google.android.gms.internal.ads.C3) cVar.c;
        c3.g = Boolean.FALSE;
        C3484k4 c3484k4 = new C3484k4(c3);
        com.quizlet.data.repository.folderset.c cVar2 = (com.quizlet.data.repository.folderset.c) cVar.b;
        cVar2.b = c3484k4;
        try {
            O4.b();
            O4 o4 = O4.c;
            C3483k3 c3483k3 = new C3483k3(cVar2);
            com.quizlet.data.repository.classfolder.e eVar = new com.quizlet.data.repository.classfolder.e(7);
            o4.a(eVar);
            pVar.a(new com.google.android.datatransport.a(new com.quizlet.data.repository.course.membership.c(false, new HashMap((HashMap) eVar.b), new HashMap((HashMap) eVar.c), (C3443e) eVar.d).s(c3483k3), com.google.android.datatransport.d.b, null), new com.facebook.appevents.k(16));
        } catch (UnsupportedEncodingException e) {
            throw new UnsupportedOperationException("Failed to covert logging to UTF-8 byte array", e);
        }
    }
}
