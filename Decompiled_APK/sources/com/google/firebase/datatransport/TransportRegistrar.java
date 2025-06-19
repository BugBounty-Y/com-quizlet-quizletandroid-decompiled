package com.google.firebase.datatransport;

import android.content.Context;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import com.google.android.datatransport.f;
import com.google.android.datatransport.runtime.q;
import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3700q;
import com.google.firebase.components.ComponentRegistrar;
import com.google.firebase.components.j;
import com.google.firebase.components.n;
import java.util.Arrays;
import java.util.List;

@Keep
/* loaded from: classes2.dex */
public class TransportRegistrar implements ComponentRegistrar {
    private static final String LIBRARY_NAME = "fire-transport";

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ f lambda$getComponents$0(com.google.firebase.components.b bVar) {
        q.b((Context) bVar.get(Context.class));
        return q.a().c(com.google.android.datatransport.cct.a.f);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ f lambda$getComponents$1(com.google.firebase.components.b bVar) {
        q.b((Context) bVar.get(Context.class));
        return q.a().c(com.google.android.datatransport.cct.a.f);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ f lambda$getComponents$2(com.google.firebase.components.b bVar) {
        q.b((Context) bVar.get(Context.class));
        return q.a().c(com.google.android.datatransport.cct.a.e);
    }

    @Override // com.google.firebase.components.ComponentRegistrar
    @NonNull
    public List<com.google.firebase.components.a> getComponents() {
        C2537qm c2537qmB = com.google.firebase.components.a.b(f.class);
        c2537qmB.a = LIBRARY_NAME;
        c2537qmB.a(j.c(Context.class));
        c2537qmB.f = new n(13);
        com.google.firebase.components.a aVarB = c2537qmB.b();
        C2537qm c2537qmA = com.google.firebase.components.a.a(new com.google.firebase.components.q(a.class, f.class));
        c2537qmA.a(j.c(Context.class));
        c2537qmA.f = new n(14);
        com.google.firebase.components.a aVarB2 = c2537qmA.b();
        C2537qm c2537qmA2 = com.google.firebase.components.a.a(new com.google.firebase.components.q(b.class, f.class));
        c2537qmA2.a(j.c(Context.class));
        c2537qmA2.f = new n(15);
        return Arrays.asList(aVarB, aVarB2, c2537qmA2.b(), AbstractC3700q.a(LIBRARY_NAME, "19.0.0"));
    }
}
