package com.google.firebase.remoteconfig;

import android.content.Context;
import androidx.annotation.Keep;
import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3700q;
import com.google.firebase.components.ComponentRegistrar;
import com.google.firebase.components.j;
import com.google.firebase.components.q;
import com.google.firebase.h;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

@Keep
/* loaded from: classes2.dex */
public class RemoteConfigRegistrar implements ComponentRegistrar {
    private static final String LIBRARY_NAME = "fire-rc";

    /* JADX INFO: Access modifiers changed from: private */
    public static f lambda$getComponents$0(q qVar, com.google.firebase.components.b bVar) {
        com.google.firebase.abt.b bVar2;
        Context context = (Context) bVar.get(Context.class);
        ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) bVar.f(qVar);
        h hVar = (h) bVar.get(h.class);
        com.google.firebase.installations.d dVar = (com.google.firebase.installations.d) bVar.get(com.google.firebase.installations.d.class);
        com.google.firebase.abt.component.a aVar = (com.google.firebase.abt.component.a) bVar.get(com.google.firebase.abt.component.a.class);
        synchronized (aVar) {
            try {
                if (!aVar.a.containsKey("frc")) {
                    aVar.a.put("frc", new com.google.firebase.abt.b(aVar.b));
                }
                bVar2 = (com.google.firebase.abt.b) aVar.a.get("frc");
            } catch (Throwable th) {
                throw th;
            }
        }
        return new f(context, scheduledExecutorService, hVar, dVar, bVar2, bVar.b(com.google.firebase.analytics.connector.b.class));
    }

    @Override // com.google.firebase.components.ComponentRegistrar
    public List<com.google.firebase.components.a> getComponents() {
        q qVar = new q(com.google.firebase.annotations.concurrent.b.class, ScheduledExecutorService.class);
        C2537qm c2537qm = new C2537qm(f.class, new Class[]{com.google.firebase.remoteconfig.interop.a.class});
        c2537qm.a = LIBRARY_NAME;
        c2537qm.a(j.c(Context.class));
        c2537qm.a(new j(qVar, 1, 0));
        c2537qm.a(j.c(h.class));
        c2537qm.a(j.c(com.google.firebase.installations.d.class));
        c2537qm.a(j.c(com.google.firebase.abt.component.a.class));
        c2537qm.a(j.a(com.google.firebase.analytics.connector.b.class));
        c2537qm.f = new com.google.firebase.heartbeatinfo.b(qVar, 3);
        c2537qm.c(2);
        return Arrays.asList(c2537qm.b(), AbstractC3700q.a(LIBRARY_NAME, "22.1.2"));
    }
}
