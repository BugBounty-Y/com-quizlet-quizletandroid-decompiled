package com.google.firebase.messaging;

import androidx.annotation.Keep;
import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3700q;
import com.google.firebase.components.ComponentRegistrar;
import java.util.Arrays;
import java.util.List;

@Keep
/* loaded from: classes2.dex */
public class FirebaseMessagingRegistrar implements ComponentRegistrar {
    private static final String LIBRARY_NAME = "fire-fcm";

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ FirebaseMessaging lambda$getComponents$0(com.google.firebase.components.q qVar, com.google.firebase.components.b bVar) {
        com.google.firebase.h hVar = (com.google.firebase.h) bVar.get(com.google.firebase.h.class);
        if (bVar.get(com.google.firebase.iid.internal.a.class) == null) {
            return new FirebaseMessaging(hVar, null, bVar.b(com.google.firebase.platforminfo.b.class), bVar.b(com.google.firebase.heartbeatinfo.g.class), (com.google.firebase.installations.d) bVar.get(com.google.firebase.installations.d.class), bVar.a(qVar), (com.google.firebase.events.c) bVar.get(com.google.firebase.events.c.class));
        }
        throw new ClassCastException();
    }

    @Override // com.google.firebase.components.ComponentRegistrar
    @Keep
    public List<com.google.firebase.components.a> getComponents() {
        com.google.firebase.components.q qVar = new com.google.firebase.components.q(com.google.firebase.datatransport.b.class, com.google.android.datatransport.f.class);
        C2537qm c2537qmB = com.google.firebase.components.a.b(FirebaseMessaging.class);
        c2537qmB.a = LIBRARY_NAME;
        c2537qmB.a(com.google.firebase.components.j.c(com.google.firebase.h.class));
        c2537qmB.a(new com.google.firebase.components.j(0, 0, com.google.firebase.iid.internal.a.class));
        c2537qmB.a(com.google.firebase.components.j.a(com.google.firebase.platforminfo.b.class));
        c2537qmB.a(com.google.firebase.components.j.a(com.google.firebase.heartbeatinfo.g.class));
        c2537qmB.a(com.google.firebase.components.j.c(com.google.firebase.installations.d.class));
        c2537qmB.a(new com.google.firebase.components.j(qVar, 0, 1));
        c2537qmB.a(com.google.firebase.components.j.c(com.google.firebase.events.c.class));
        c2537qmB.f = new com.google.firebase.heartbeatinfo.b(qVar, 1);
        c2537qmB.c(1);
        return Arrays.asList(c2537qmB.b(), AbstractC3700q.a(LIBRARY_NAME, "24.1.1"));
    }
}
