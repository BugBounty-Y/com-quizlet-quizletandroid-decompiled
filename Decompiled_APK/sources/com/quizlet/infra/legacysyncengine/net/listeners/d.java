package com.quizlet.infra.legacysyncengine.net.listeners;

import com.quizlet.db.data.net.localid.LocalIdMap;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import com.quizlet.infra.legacysyncengine.e;
import com.quizlet.infra.legacysyncengine.models.identity.QueryIdFieldChangeMapper;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes3.dex */
public final class d {
    public final e a;
    public final QueryIdFieldChangeMapper b;
    public final ConcurrentHashMap c = new ConcurrentHashMap();

    public d(LocalIdMap localIdMap, e eVar, QueryIdFieldChangeMapper queryIdFieldChangeMapper) {
        this.a = eVar;
        this.b = queryIdFieldChangeMapper;
        localIdMap.getServerIdAssignmentObservable().u(new com.quizlet.billing.subscriptions.a(this, 8), new com.quizlet.billing.subscriptions.c(3), io.reactivex.rxjava3.internal.functions.d.c);
    }

    public static void a(ArrayList arrayList, List list) {
        if (arrayList == null || list == null || list.size() <= 0) {
            return;
        }
        Iterator it2 = new ArrayList(list).iterator();
        while (it2.hasNext()) {
            com.quizlet.infra.legacysyncengine.a aVar = (com.quizlet.infra.legacysyncengine.a) it2.next();
            if (aVar == null || !list.contains(aVar)) {
                timber.log.c.a(new NullPointerException("Listener is null"));
            } else {
                aVar.a(arrayList);
            }
        }
    }

    public final void b(com.quizlet.infra.legacysyncengine.orm.query.a aVar, com.quizlet.infra.legacysyncengine.a aVar2) {
        IdMappedQuery idMappedQueryConvertStaleLocalIds = this.b.convertStaleLocalIds(aVar);
        if (idMappedQueryConvertStaleLocalIds != null) {
            this.c.compute(idMappedQueryConvertStaleLocalIds, new a(this, aVar2, 0));
            return;
        }
        timber.log.c.a(new RuntimeException("Tried to register null query for listener: " + aVar2));
    }
}
