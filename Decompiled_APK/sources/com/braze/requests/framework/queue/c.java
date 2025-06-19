package com.braze.requests.framework.queue;

import androidx.navigation.compose.C1277j;
import com.braze.H;
import com.braze.models.outgoing.k;
import com.braze.requests.m;
import com.braze.requests.n;
import com.braze.support.BrazeLogger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c extends com.braze.requests.framework.b {
    public static final String k = BrazeLogger.getBrazeLogTag((Class<?>) c.class);

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(com.braze.dispatch.h dispatchDataProvider) {
        super(m.f, dispatchDataProvider);
        Intrinsics.checkNotNullParameter(dispatchDataProvider, "dispatchDataProvider");
    }

    public final void a(long j, com.braze.requests.framework.h hVar, List list) {
        com.braze.models.b bVar;
        com.braze.models.b bVar2;
        com.braze.requests.framework.h hVar2 = hVar;
        n nVar = hVar2 != null ? hVar2.a : null;
        com.braze.requests.f fVar = nVar instanceof com.braze.requests.f ? (com.braze.requests.f) nVar : null;
        if (fVar == null) {
            return;
        }
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            com.braze.requests.framework.h hVar3 = (com.braze.requests.framework.h) it2.next();
            n nVar2 = hVar3.a;
            com.braze.requests.f fVar2 = nVar2 instanceof com.braze.requests.f ? (com.braze.requests.f) nVar2 : null;
            if (fVar2 != null && ((fVar.l == null || fVar2.l == null) && (((bVar = fVar.m) == null || bVar.b) && ((bVar2 = fVar2.m) == null || bVar2.b)))) {
                k kVar = fVar2.j;
                k kVar2 = fVar.j;
                Boolean bool = (kVar2.b == null && kVar.b == null) ? null : Boolean.TRUE;
                Boolean bool2 = (kVar2.b() || kVar.b()) ? Boolean.TRUE : null;
                com.braze.models.outgoing.i outboundConfigParams = fVar.j.d;
                if (outboundConfigParams != null) {
                    Intrinsics.checkNotNullParameter(outboundConfigParams, "outboundConfigParams");
                } else {
                    outboundConfigParams = null;
                }
                com.braze.models.outgoing.i outboundConfigParams2 = kVar.d;
                if (outboundConfigParams2 != null) {
                    Intrinsics.checkNotNullParameter(outboundConfigParams2, "outboundConfigParams");
                    outboundConfigParams = outboundConfigParams2;
                }
                String str = fVar.j.a;
                if (str == null) {
                    str = null;
                }
                String str2 = kVar.a;
                if (str2 != null) {
                    str = str2;
                }
                fVar.j = new k(str, bool, bool2, outboundConfigParams);
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, k, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new H(hVar3, j, hVar2, 4), 14, (Object) null);
                hVar3.a(j, com.braze.requests.framework.i.d);
                hVar2 = hVar;
            } else {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1277j(18, fVar2, hVar2), 7, (Object) null);
            }
        }
    }

    @Override // com.braze.requests.framework.b
    public final void a(long j) {
        ArrayList arrayList = this.e;
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (((com.braze.requests.framework.h) next).d.a()) {
                arrayList2.add(next);
            }
        }
        List listN0 = CollectionsKt.n0(arrayList2, new b());
        int size = listN0.size();
        if (size < 2) {
            return;
        }
        a(j, (com.braze.requests.framework.h) CollectionsKt.L(listN0), listN0.subList(1, size));
    }

    public static final String a(com.braze.requests.framework.h hVar, long j, com.braze.requests.framework.h hVar2) {
        return "Batched request " + hVar.a(j) + " and combined into " + hVar2.a(j);
    }

    public static final String a(com.braze.requests.f fVar, com.braze.requests.framework.h hVar) {
        return "Could not merge other request: " + fVar + " into parent: " + hVar;
    }
}
