package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import androidx.appcompat.widget.C0122z;

/* loaded from: classes2.dex */
public final class L7 implements G7 {
    public final com.google.firebase.components.l a;
    public final com.google.firebase.components.l b;
    public final F7 c;

    public L7(Context context, F7 f7) {
        this.c = f7;
        com.google.android.datatransport.cct.a aVar = com.google.android.datatransport.cct.a.e;
        com.google.android.datatransport.runtime.q.b(context);
        com.google.android.datatransport.runtime.o oVarC = com.google.android.datatransport.runtime.q.a().c(aVar);
        if (com.google.android.datatransport.cct.a.d.contains(new com.google.android.datatransport.c("json"))) {
            this.a = new com.google.firebase.components.l(new K7(oVarC, 0));
        }
        this.b = new com.google.firebase.components.l(new K7(oVarC, 1));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.G7
    public final void a(C0122z c0122z) {
        F7 f7 = this.c;
        int i = f7.b;
        com.google.android.datatransport.d dVar = com.google.android.datatransport.d.b;
        int i2 = f7.b;
        if (i != 0) {
            ((com.google.android.datatransport.runtime.p) this.b.get()).a(c0122z.b != 0 ? com.google.android.datatransport.a.a(c0122z.B(i2)) : new com.google.android.datatransport.a(c0122z.B(i2), dVar, null), new com.facebook.appevents.k(16));
            return;
        }
        com.google.firebase.components.l lVar = this.a;
        if (lVar != null) {
            ((com.google.android.datatransport.runtime.p) lVar.get()).a(c0122z.b != 0 ? com.google.android.datatransport.a.a(c0122z.B(i2)) : new com.google.android.datatransport.a(c0122z.B(i2), dVar, null), new com.facebook.appevents.k(16));
        }
    }
}
