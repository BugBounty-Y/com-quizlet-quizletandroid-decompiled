package com.google.firebase.crashlytics;

import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3700q;
import com.google.firebase.components.ComponentRegistrar;
import com.google.firebase.components.j;
import com.google.firebase.components.q;
import com.google.firebase.h;
import com.google.firebase.sessions.api.d;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class CrashlyticsRegistrar implements ComponentRegistrar {
    public static final /* synthetic */ int d = 0;
    public final q a = new q(com.google.firebase.annotations.concurrent.a.class, ExecutorService.class);
    public final q b = new q(com.google.firebase.annotations.concurrent.b.class, ExecutorService.class);
    public final q c = new q(com.google.firebase.annotations.concurrent.c.class, ExecutorService.class);

    static {
        d subscriberName = d.a;
        com.google.firebase.sessions.api.c cVar = com.google.firebase.sessions.api.c.a;
        Intrinsics.checkNotNullParameter(subscriberName, "subscriberName");
        Map dependencies = com.google.firebase.sessions.api.c.b;
        if (dependencies.containsKey(subscriberName)) {
            Objects.toString(subscriberName);
            return;
        }
        Intrinsics.checkNotNullExpressionValue(dependencies, "dependencies");
        dependencies.put(subscriberName, new com.google.firebase.sessions.api.a(new kotlinx.coroutines.sync.c(true)));
        Objects.toString(subscriberName);
    }

    @Override // com.google.firebase.components.ComponentRegistrar
    public final List getComponents() {
        C2537qm c2537qmB = com.google.firebase.components.a.b(b.class);
        c2537qmB.a = "fire-cls";
        c2537qmB.a(j.c(h.class));
        c2537qmB.a(j.c(com.google.firebase.installations.d.class));
        c2537qmB.a(new j(this.a, 1, 0));
        c2537qmB.a(new j(this.b, 1, 0));
        c2537qmB.a(new j(this.c, 1, 0));
        c2537qmB.a(new j(0, 2, com.google.firebase.crashlytics.internal.a.class));
        c2537qmB.a(new j(0, 2, com.google.firebase.analytics.connector.b.class));
        c2537qmB.a(new j(0, 2, com.google.firebase.remoteconfig.interop.a.class));
        c2537qmB.f = new com.google.android.material.search.a(this, 3);
        c2537qmB.c(2);
        return Arrays.asList(c2537qmB.b(), AbstractC3700q.a("fire-cls", "19.4.3"));
    }
}
