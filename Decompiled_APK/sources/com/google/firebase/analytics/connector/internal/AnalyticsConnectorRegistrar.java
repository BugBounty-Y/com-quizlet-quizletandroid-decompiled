package com.google.firebase.analytics.connector.internal;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Bundle;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.measurement.C3008j0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3700q;
import com.google.firebase.components.ComponentRegistrar;
import com.google.firebase.components.j;
import com.google.firebase.components.k;
import com.google.firebase.events.c;
import com.google.firebase.h;
import java.util.Arrays;
import java.util.List;

@Keep
/* loaded from: classes2.dex */
public class AnalyticsConnectorRegistrar implements ComponentRegistrar {
    public static com.google.firebase.analytics.connector.b lambda$getComponents$0(com.google.firebase.components.b bVar) {
        h hVar = (h) bVar.get(h.class);
        Context context = (Context) bVar.get(Context.class);
        c cVar = (c) bVar.get(c.class);
        u.h(hVar);
        u.h(context);
        u.h(cVar);
        u.h(context.getApplicationContext());
        if (com.google.firebase.analytics.connector.c.c == null) {
            synchronized (com.google.firebase.analytics.connector.c.class) {
                try {
                    if (com.google.firebase.analytics.connector.c.c == null) {
                        Bundle bundle = new Bundle(1);
                        hVar.a();
                        if ("[DEFAULT]".equals(hVar.b)) {
                            ((k) cVar).a(new androidx.camera.core.impl.utils.executor.a(6), new com.google.mlkit.common.internal.model.a(18));
                            bundle.putBoolean("dataCollectionDefaultEnabled", hVar.h());
                        }
                        com.google.firebase.analytics.connector.c.c = new com.google.firebase.analytics.connector.c(C3008j0.f(context, null, null, null, bundle).d);
                    }
                } finally {
                }
            }
        }
        return com.google.firebase.analytics.connector.c.c;
    }

    @Override // com.google.firebase.components.ComponentRegistrar
    @NonNull
    @Keep
    @SuppressLint({"MissingPermission"})
    public List<com.google.firebase.components.a> getComponents() {
        C2537qm c2537qmB = com.google.firebase.components.a.b(com.google.firebase.analytics.connector.b.class);
        c2537qmB.a(j.c(h.class));
        c2537qmB.a(j.c(Context.class));
        c2537qmB.a(j.c(c.class));
        c2537qmB.f = new com.google.firebase.perf.logging.b(18);
        c2537qmB.c(2);
        return Arrays.asList(c2537qmB.b(), AbstractC3700q.a("fire-analytics", "22.4.0"));
    }
}
