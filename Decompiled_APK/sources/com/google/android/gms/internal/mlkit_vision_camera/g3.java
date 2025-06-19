package com.google.android.gms.internal.mlkit_vision_camera;

import android.content.Context;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_barcode.K7;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class g3 implements e3 {
    public final com.google.firebase.components.l a;
    public final b3 b;

    public g3(Context context, b3 b3Var) {
        this.b = b3Var;
        com.google.android.datatransport.cct.a aVar = com.google.android.datatransport.cct.a.e;
        com.google.android.datatransport.runtime.q.b(context);
        com.google.android.datatransport.runtime.o oVarC = com.google.android.datatransport.runtime.q.a().c(aVar);
        if (com.google.android.datatransport.cct.a.d.contains(new com.google.android.datatransport.c("json"))) {
            new com.google.firebase.components.l(new K7(oVarC, 2));
        }
        this.a = new com.google.firebase.components.l(new K7(oVarC, 3));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.e3
    public final void a(com.quizlet.data.repository.explanations.myexplanations.a aVar) {
        b3 b3Var = this.b;
        b3Var.getClass();
        com.google.android.datatransport.runtime.p pVar = (com.google.android.datatransport.runtime.p) this.a.get();
        b3Var.getClass();
        ((C3) aVar.c).i = false;
        C3 c3 = (C3) aVar.c;
        c3.g = Boolean.FALSE;
        I2 i2 = new I2(c3);
        io.ktor.client.plugins.api.d dVar = (io.ktor.client.plugins.api.d) aVar.b;
        dVar.b = i2;
        try {
            i3.b();
            i3 i3Var = i3.c;
            C3323b2 c3323b2 = new C3323b2(dVar);
            com.google.android.gms.internal.appset.e eVar = new com.google.android.gms.internal.appset.e(7);
            i3Var.a(eVar);
            pVar.a(com.google.android.datatransport.a.a(new com.quizlet.data.interactor.set.c(new HashMap((HashMap) eVar.b), new HashMap((HashMap) eVar.c), (C3319a2) eVar.d).s(c3323b2)), new com.facebook.appevents.k(16));
        } catch (UnsupportedEncodingException e) {
            throw new UnsupportedOperationException("Failed to covert logging to UTF-8 byte array", e);
        }
    }
}
