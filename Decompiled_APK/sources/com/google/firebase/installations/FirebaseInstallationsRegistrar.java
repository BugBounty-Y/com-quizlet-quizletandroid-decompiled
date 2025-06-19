package com.google.firebase.installations;

import androidx.annotation.Keep;
import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3700q;
import com.google.firebase.components.ComponentRegistrar;
import com.google.firebase.components.j;
import com.google.firebase.components.n;
import com.google.firebase.components.q;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;

@Keep
/* loaded from: classes2.dex */
public class FirebaseInstallationsRegistrar implements ComponentRegistrar {
    private static final String LIBRARY_NAME = "fire-installations";

    /* JADX INFO: Access modifiers changed from: private */
    public static d lambda$getComponents$0(com.google.firebase.components.b bVar) {
        return new c((com.google.firebase.h) bVar.get(com.google.firebase.h.class), bVar.b(com.google.firebase.heartbeatinfo.f.class), (ExecutorService) bVar.f(new q(com.google.firebase.annotations.concurrent.a.class, ExecutorService.class)), new com.google.firebase.concurrent.i((Executor) bVar.f(new q(com.google.firebase.annotations.concurrent.b.class, Executor.class))));
    }

    @Override // com.google.firebase.components.ComponentRegistrar
    public List<com.google.firebase.components.a> getComponents() {
        C2537qm c2537qmB = com.google.firebase.components.a.b(d.class);
        c2537qmB.a = LIBRARY_NAME;
        c2537qmB.a(j.c(com.google.firebase.h.class));
        c2537qmB.a(j.a(com.google.firebase.heartbeatinfo.f.class));
        c2537qmB.a(new j(new q(com.google.firebase.annotations.concurrent.a.class, ExecutorService.class), 1, 0));
        c2537qmB.a(new j(new q(com.google.firebase.annotations.concurrent.b.class, Executor.class), 1, 0));
        c2537qmB.f = new n(16);
        com.google.firebase.components.a aVarB = c2537qmB.b();
        com.google.firebase.heartbeatinfo.e eVar = new com.google.firebase.heartbeatinfo.e(0);
        C2537qm c2537qmB2 = com.google.firebase.components.a.b(com.google.firebase.heartbeatinfo.e.class);
        c2537qmB2.c = 1;
        c2537qmB2.f = new com.google.android.material.search.a(eVar, 2);
        return Arrays.asList(aVarB, c2537qmB2.b(), AbstractC3700q.a(LIBRARY_NAME, "18.0.0"));
    }
}
