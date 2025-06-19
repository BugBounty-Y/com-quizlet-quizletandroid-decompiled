package com.quizlet.infra.legacysyncengine;

import com.quizlet.db.data.models.base.RelationshipGraph;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import com.quizlet.infra.legacysyncengine.net.g;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes3.dex */
public final class e {
    public final RelationshipGraph a;
    public final ConcurrentHashMap b = new ConcurrentHashMap();

    public e(RelationshipGraph relationshipGraph) {
        this.a = relationshipGraph;
    }

    public final ArrayList a(IdMappedQuery idMappedQuery) {
        List list;
        g gVar = (g) this.b.get(idMappedQuery);
        if (gVar == null || (list = gVar.a) == null) {
            return null;
        }
        return new ArrayList(list);
    }
}
