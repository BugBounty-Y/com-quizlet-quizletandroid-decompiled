package com.google.firebase.analytics.connector;

import android.os.Bundle;
import androidx.appcompat.app.Q;
import androidx.work.impl.model.l;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.measurement.C2983e0;
import com.google.android.gms.internal.measurement.C3008j0;
import com.google.firebase.heartbeatinfo.e;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes2.dex */
public final class c implements b {
    public static volatile c c;
    public final Q a;
    public final ConcurrentHashMap b;

    public c(Q q) {
        u.h(q);
        this.a = q;
        this.b = new ConcurrentHashMap();
    }

    public final void a(String str, String str2, Bundle bundle) {
        if (com.google.firebase.analytics.connector.internal.a.c(str) && com.google.firebase.analytics.connector.internal.a.b(bundle, str2) && com.google.firebase.analytics.connector.internal.a.a(str, str2, bundle)) {
            if ("clx".equals(str) && "_ae".equals(str2)) {
                bundle.putLong("_r", 1L);
            }
            C3008j0 c3008j0 = (C3008j0) this.a.a;
            c3008j0.getClass();
            c3008j0.c(new C2983e0(c3008j0, null, str, str2, bundle, true, true));
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v9, types: [androidx.work.impl.model.c] */
    public final e b(l lVar, String str) {
        com.google.firebase.platforminfo.c cVar;
        if (com.google.firebase.analytics.connector.internal.a.c(str)) {
            boolean zIsEmpty = str.isEmpty();
            ConcurrentHashMap concurrentHashMap = this.b;
            if (zIsEmpty || !concurrentHashMap.containsKey(str) || concurrentHashMap.get(str) == null) {
                boolean zEquals = "fiam".equals(str);
                Q q = this.a;
                if (zEquals) {
                    cVar = new androidx.work.impl.model.c(q, lVar);
                } else if ("clx".equals(str)) {
                    com.google.firebase.platforminfo.c cVar2 = new com.google.firebase.platforminfo.c();
                    cVar2.a = lVar;
                    ((C3008j0) q.a).a(new com.google.firebase.analytics.connector.internal.b(cVar2, 1));
                    cVar = cVar2;
                } else {
                    cVar = null;
                }
                if (cVar != null) {
                    concurrentHashMap.put(str, cVar);
                    return new e(18);
                }
            }
        }
        return null;
    }
}
