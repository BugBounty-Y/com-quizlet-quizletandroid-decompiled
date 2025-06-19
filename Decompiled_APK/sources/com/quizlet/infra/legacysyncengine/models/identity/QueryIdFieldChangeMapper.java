package com.quizlet.infra.legacysyncengine.models.identity;

import com.google.android.gms.internal.common.g;
import com.google.common.collect.o;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.base.RelationshipGraph;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.net.localid.LocalIdMap;
import com.quizlet.db.data.orm.Filter;
import com.quizlet.db.data.orm.Include;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.db.data.orm.query.BaseQuery;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/* loaded from: classes3.dex */
public class QueryIdFieldChangeMapper {
    protected final LocalIdMap mLocalIdMap;
    protected final RelationshipGraph mRelationshipGraph;

    public QueryIdFieldChangeMapper(RelationshipGraph relationshipGraph, LocalIdMap localIdMap) {
        this.mRelationshipGraph = relationshipGraph;
        this.mLocalIdMap = localIdMap;
    }

    public <N extends DBModel> IdMappedQuery<N> convertStaleLocalIds(BaseQuery<N> baseQuery) {
        IdMappedQuery<N> idMappedQueryRemapQueryForServerIdAssignment = remapQueryForServerIdAssignment(baseQuery);
        return idMappedQueryRemapQueryForServerIdAssignment != null ? idMappedQueryRemapQueryForServerIdAssignment : new IdMappedQuery<>(baseQuery);
    }

    public Set<Long> getNegativeValues(Set<Long> set) {
        HashSet hashSet = new HashSet();
        for (Long l : set) {
            if (l.longValue() < 0) {
                hashSet.add(l);
            }
        }
        return hashSet;
    }

    public boolean hasNegativeValues(Set<Long> set) {
        Iterator<Long> it2 = set.iterator();
        while (it2.hasNext()) {
            if (it2.next().longValue() < 0) {
                return true;
            }
        }
        return false;
    }

    public Map<IdMappedQuery, IdMappedQuery> remapQueriesForServerIdAssignment(Set<IdMappedQuery> set) {
        HashMap map = new HashMap();
        for (IdMappedQuery idMappedQuery : set) {
            IdMappedQuery idMappedQueryRemapQueryForServerIdAssignment = remapQueryForServerIdAssignment(idMappedQuery);
            if (idMappedQueryRemapQueryForServerIdAssignment != null) {
                map.put(idMappedQuery, idMappedQueryRemapQueryForServerIdAssignment);
            }
        }
        return map;
    }

    public <N extends DBModel> IdMappedQuery<N> remapQueryForServerIdAssignment(BaseQuery<N> baseQuery) {
        g it2 = baseQuery.getFilters().iterator();
        HashSet hashSet = null;
        HashMap map = null;
        while (it2.hasNext()) {
            Filter<N> filter = (Filter) it2.next();
            Filter<N> filterTryUpdateFilter = tryUpdateFilter(filter);
            if (filterTryUpdateFilter != null) {
                if (map == null) {
                    map = new HashMap();
                }
                map.put(filter, filterTryUpdateFilter);
            }
        }
        if (map == null) {
            return null;
        }
        HashSet hashSet2 = new HashSet();
        g it3 = baseQuery.getFilters().iterator();
        while (it3.hasNext()) {
            Filter filter2 = (Filter) it3.next();
            Filter filter3 = (Filter) map.get(filter2);
            if (filter3 == null) {
                hashSet2.add(filter2.clone());
            } else {
                hashSet2.add(filter3);
            }
        }
        o oVarN = o.n(hashSet2);
        if (baseQuery.getIncludes() != null) {
            hashSet = new HashSet();
            Iterator<Include> it4 = baseQuery.getIncludes().iterator();
            while (it4.hasNext()) {
                hashSet.add(new Include(it4.next().a));
            }
        }
        return new IdMappedQuery<>(baseQuery.getModelType(), oVarN, hashSet);
    }

    public <N extends DBModel> Set<Long> tryReplaceNegativeValues(ModelType<N> modelType, Set<Long> set) {
        HashSet hashSet = null;
        for (Long l : getNegativeValues(set)) {
            Long lA = this.mLocalIdMap.a(modelType, l);
            if (lA != null) {
                if (hashSet == null) {
                    hashSet = new HashSet(set);
                }
                hashSet.remove(l);
                hashSet.add(lA);
            }
        }
        return hashSet;
    }

    public <N extends DBModel> Filter<N> tryUpdateFilter(Filter<N> filter) {
        if (!hasNegativeValues(filter.getFieldValues())) {
            return null;
        }
        if (filter.getField().getDatabaseColumnName().equals("localGeneratedId")) {
            Set<Long> setTryReplaceNegativeValues = tryReplaceNegativeValues(filter.getField().getModelType(), filter.getFieldValues());
            if (setTryReplaceNegativeValues != null) {
                return new Filter<>(ModelIdentityProvider.getSingleIdentityField(filter.getField().getModelType()), setTryReplaceNegativeValues);
            }
            return null;
        }
        for (Relationship<N, ? extends DBModel> relationship : this.mRelationshipGraph.getToOneRelationships(filter.getField().getModelType())) {
            if (relationship.equals(filter.getField())) {
                Set<Long> setTryReplaceNegativeValues2 = tryReplaceNegativeValues(filter.d(relationship), filter.getFieldValues());
                if (setTryReplaceNegativeValues2 != null) {
                    return filter.c(setTryReplaceNegativeValues2);
                }
                return null;
            }
        }
        return null;
    }
}
