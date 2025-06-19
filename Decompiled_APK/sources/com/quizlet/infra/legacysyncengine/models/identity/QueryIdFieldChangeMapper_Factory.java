package com.quizlet.infra.legacysyncengine.models.identity;

import com.quizlet.db.data.models.base.RelationshipGraph;
import com.quizlet.db.data.net.localid.LocalIdMap;
import dagger.internal.c;

/* loaded from: classes3.dex */
public final class QueryIdFieldChangeMapper_Factory implements c {
    private final c localIdMapProvider;
    private final c relationshipGraphProvider;

    public QueryIdFieldChangeMapper_Factory(c cVar, c cVar2) {
        this.relationshipGraphProvider = cVar;
        this.localIdMapProvider = cVar2;
    }

    public static QueryIdFieldChangeMapper_Factory create(c cVar, c cVar2) {
        return new QueryIdFieldChangeMapper_Factory(cVar, cVar2);
    }

    public static QueryIdFieldChangeMapper newInstance(RelationshipGraph relationshipGraph, LocalIdMap localIdMap) {
        return new QueryIdFieldChangeMapper(relationshipGraph, localIdMap);
    }

    @Override // javax.inject.a
    public QueryIdFieldChangeMapper get() {
        return newInstance((RelationshipGraph) this.relationshipGraphProvider.get(), (LocalIdMap) this.localIdMapProvider.get());
    }
}
