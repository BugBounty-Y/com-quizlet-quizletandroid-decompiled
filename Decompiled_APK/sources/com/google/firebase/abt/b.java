package com.google.firebase.abt;

import android.os.Bundle;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.measurement.C3008j0;
import com.google.android.gms.measurement.internal.AbstractC3883n0;
import com.google.common.collect.o;
import com.google.firebase.analytics.connector.c;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class b {
    public final com.google.firebase.inject.b a;
    public Integer b = null;

    public b(com.google.firebase.inject.b bVar) {
        this.a = bVar;
    }

    public static boolean a(ArrayList arrayList, a aVar) {
        String str = aVar.a;
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            a aVar2 = (a) it2.next();
            if (aVar2.a.equals(str) && aVar2.b.equals(aVar.b)) {
                return true;
            }
        }
        return false;
    }

    public final ArrayList b() {
        c cVar = (c) ((com.google.firebase.analytics.connector.b) this.a.get());
        cVar.getClass();
        ArrayList arrayList = new ArrayList();
        for (Bundle bundle : ((C3008j0) cVar.a.a).g("frc", "")) {
            o oVar = com.google.firebase.analytics.connector.internal.a.a;
            u.h(bundle);
            com.google.firebase.analytics.connector.a aVar = new com.google.firebase.analytics.connector.a();
            String str = (String) AbstractC3883n0.a(bundle, "origin", String.class, null);
            u.h(str);
            aVar.a = str;
            String str2 = (String) AbstractC3883n0.a(bundle, "name", String.class, null);
            u.h(str2);
            aVar.b = str2;
            aVar.c = AbstractC3883n0.a(bundle, "value", Object.class, null);
            aVar.d = (String) AbstractC3883n0.a(bundle, "trigger_event_name", String.class, null);
            aVar.e = ((Long) AbstractC3883n0.a(bundle, "trigger_timeout", Long.class, 0L)).longValue();
            aVar.f = (String) AbstractC3883n0.a(bundle, "timed_out_event_name", String.class, null);
            aVar.g = (Bundle) AbstractC3883n0.a(bundle, "timed_out_event_params", Bundle.class, null);
            aVar.h = (String) AbstractC3883n0.a(bundle, "triggered_event_name", String.class, null);
            aVar.i = (Bundle) AbstractC3883n0.a(bundle, "triggered_event_params", Bundle.class, null);
            aVar.j = ((Long) AbstractC3883n0.a(bundle, "time_to_live", Long.class, 0L)).longValue();
            aVar.k = (String) AbstractC3883n0.a(bundle, "expired_event_name", String.class, null);
            aVar.l = (Bundle) AbstractC3883n0.a(bundle, "expired_event_params", Bundle.class, null);
            aVar.n = ((Boolean) AbstractC3883n0.a(bundle, "active", Boolean.class, Boolean.FALSE)).booleanValue();
            aVar.m = ((Long) AbstractC3883n0.a(bundle, "creation_timestamp", Long.class, 0L)).longValue();
            aVar.o = ((Long) AbstractC3883n0.a(bundle, "triggered_timestamp", Long.class, 0L)).longValue();
            arrayList.add(aVar);
        }
        return arrayList;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:101:0x0295  */
    /* JADX WARN: Type inference failed for: r12v1, types: [java.io.ObjectOutputStream] */
    /* JADX WARN: Type inference failed for: r12v16 */
    /* JADX WARN: Type inference failed for: r12v17 */
    /* JADX WARN: Type inference failed for: r12v18 */
    /* JADX WARN: Type inference failed for: r13v0 */
    /* JADX WARN: Type inference failed for: r13v1, types: [java.io.ObjectInputStream] */
    /* JADX WARN: Type inference failed for: r13v11 */
    /* JADX WARN: Type inference failed for: r13v2 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(java.util.ArrayList r22) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 904
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.abt.b.c(java.util.ArrayList):void");
    }
}
