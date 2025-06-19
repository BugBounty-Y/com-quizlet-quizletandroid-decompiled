package com.google.firebase.perf;

import android.app.Application;
import android.content.Context;
import androidx.annotation.Keep;
import androidx.lifecycle.d0;
import com.google.android.gms.common.api.internal.w;
import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3692p;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3700q;
import com.google.firebase.components.ComponentRegistrar;
import com.google.firebase.components.j;
import com.google.firebase.components.n;
import com.google.firebase.components.q;
import com.google.firebase.h;
import com.google.firebase.perf.metrics.AppStartTrace;
import com.google.firebase.perf.session.SessionManager;
import com.google.firebase.perf.transport.f;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

@Keep
/* loaded from: classes2.dex */
public class FirebasePerfRegistrar implements ComponentRegistrar {
    private static final String EARLY_LIBRARY_NAME = "fire-perf-early";
    private static final String LIBRARY_NAME = "fire-perf";

    /* JADX INFO: Access modifiers changed from: private */
    public static a lambda$getComponents$0(q qVar, com.google.firebase.components.b bVar) {
        AppStartTrace appStartTrace;
        h hVar = (h) bVar.get(h.class);
        com.google.firebase.a aVar = (com.google.firebase.a) bVar.b(com.google.firebase.a.class).get();
        Executor executor = (Executor) bVar.f(qVar);
        a aVar2 = new a();
        hVar.a();
        Context context = hVar.a;
        com.google.firebase.perf.config.a aVarE = com.google.firebase.perf.config.a.e();
        aVarE.getClass();
        com.google.firebase.perf.config.a.d.b = AbstractC3692p.a(context);
        aVarE.c.c(context);
        com.google.firebase.perf.application.c cVarA = com.google.firebase.perf.application.c.a();
        synchronized (cVarA) {
            if (!cVarA.p) {
                Context applicationContext = context.getApplicationContext();
                if (applicationContext instanceof Application) {
                    ((Application) applicationContext).registerActivityLifecycleCallbacks(cVarA);
                    cVarA.p = true;
                }
            }
        }
        c cVar = new c();
        synchronized (cVarA.g) {
            cVarA.g.add(cVar);
        }
        if (aVar != null) {
            if (AppStartTrace.x != null) {
                appStartTrace = AppStartTrace.x;
            } else {
                f fVar = f.s;
                assistantMode.utils.studiableMetadata.b bVar2 = new assistantMode.utils.studiableMetadata.b(19);
                if (AppStartTrace.x == null) {
                    synchronized (AppStartTrace.class) {
                        try {
                            if (AppStartTrace.x == null) {
                                AppStartTrace.x = new AppStartTrace(fVar, bVar2, com.google.firebase.perf.config.a.e(), new ThreadPoolExecutor(0, 1, 10 + AppStartTrace.w, TimeUnit.SECONDS, new LinkedBlockingQueue()));
                            }
                        } finally {
                        }
                    }
                }
                appStartTrace = AppStartTrace.x;
            }
            synchronized (appStartTrace) {
                if (!appStartTrace.a) {
                    d0.i.f.a(appStartTrace);
                    Context applicationContext2 = context.getApplicationContext();
                    if (applicationContext2 instanceof Application) {
                        ((Application) applicationContext2).registerActivityLifecycleCallbacks(appStartTrace);
                        appStartTrace.u = appStartTrace.u || AppStartTrace.c((Application) applicationContext2);
                        appStartTrace.a = true;
                        appStartTrace.e = (Application) applicationContext2;
                    }
                }
            }
            executor.execute(new w(appStartTrace, 14));
        }
        SessionManager.getInstance().initializeGaugeCollection();
        return aVar2;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static b providesFirebasePerformance(com.google.firebase.components.b bVar) {
        bVar.get(a.class);
        com.quizlet.data.repository.explanations.exercise.b bVar2 = new com.quizlet.data.repository.explanations.exercise.b((h) bVar.get(h.class), (com.google.firebase.installations.d) bVar.get(com.google.firebase.installations.d.class), bVar.b(com.google.firebase.remoteconfig.f.class), bVar.b(com.google.android.datatransport.f.class));
        return (b) ((dagger.internal.a) dagger.internal.a.b(new d(new com.google.firebase.perf.injection.modules.b(bVar2, 0), new com.google.firebase.perf.injection.modules.b(bVar2, 2), new com.google.firebase.perf.injection.modules.b(bVar2, 1), new com.google.firebase.perf.injection.modules.b(bVar2, 3), new com.google.firebase.perf.injection.modules.a(bVar2, 1), new com.google.firebase.perf.injection.modules.a(bVar2, 0), new com.google.firebase.perf.injection.modules.a(bVar2, 2)))).get();
    }

    @Override // com.google.firebase.components.ComponentRegistrar
    @Keep
    public List<com.google.firebase.components.a> getComponents() {
        q qVar = new q(com.google.firebase.annotations.concurrent.d.class, Executor.class);
        C2537qm c2537qmB = com.google.firebase.components.a.b(b.class);
        c2537qmB.a = LIBRARY_NAME;
        c2537qmB.a(j.c(h.class));
        c2537qmB.a(new j(1, 1, com.google.firebase.remoteconfig.f.class));
        c2537qmB.a(j.c(com.google.firebase.installations.d.class));
        c2537qmB.a(new j(1, 1, com.google.android.datatransport.f.class));
        c2537qmB.a(j.c(a.class));
        c2537qmB.f = new n(21);
        com.google.firebase.components.a aVarB = c2537qmB.b();
        C2537qm c2537qmB2 = com.google.firebase.components.a.b(a.class);
        c2537qmB2.a = EARLY_LIBRARY_NAME;
        c2537qmB2.a(j.c(h.class));
        c2537qmB2.a(j.a(com.google.firebase.a.class));
        c2537qmB2.a(new j(qVar, 1, 0));
        c2537qmB2.c(2);
        c2537qmB2.f = new com.google.firebase.heartbeatinfo.b(qVar, 2);
        return Arrays.asList(aVarB, c2537qmB2.b(), AbstractC3700q.a(LIBRARY_NAME, "21.0.5"));
    }
}
