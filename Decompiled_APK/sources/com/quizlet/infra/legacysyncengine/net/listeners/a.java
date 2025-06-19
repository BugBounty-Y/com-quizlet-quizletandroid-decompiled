package com.quizlet.infra.legacysyncengine.net.listeners;

import com.quizlet.db.data.orm.query.IdMappedQuery;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements BiFunction {
    public final /* synthetic */ int a;
    public final /* synthetic */ d b;
    public final /* synthetic */ com.quizlet.infra.legacysyncengine.a c;

    public /* synthetic */ a(d dVar, com.quizlet.infra.legacysyncengine.a aVar, int i) {
        this.a = i;
        this.b = dVar;
        this.c = aVar;
    }

    @Override // java.util.function.BiFunction
    public final Object apply(Object obj, Object obj2) {
        IdMappedQuery idMappedQuery = (IdMappedQuery) obj;
        List arrayList = (List) obj2;
        switch (this.a) {
            case 0:
                d dVar = this.b;
                dVar.getClass();
                if (arrayList == null) {
                    arrayList = new ArrayList();
                }
                com.quizlet.infra.legacysyncengine.a aVar = this.c;
                if (!arrayList.contains(aVar)) {
                    arrayList.add(aVar);
                    if (aVar == null) {
                        timber.log.c.a(new NullPointerException("Null Listener being added"));
                    }
                    dVar.a.b.compute(idMappedQuery, new com.quizlet.infra.legacysyncengine.b(1));
                    break;
                }
                break;
            default:
                d dVar2 = this.b;
                dVar2.getClass();
                if (arrayList.remove(this.c)) {
                    dVar2.a.b.computeIfPresent(idMappedQuery, new com.quizlet.infra.legacysyncengine.b(2));
                }
                if (arrayList.size() == 0) {
                }
                break;
        }
        return arrayList;
    }
}
