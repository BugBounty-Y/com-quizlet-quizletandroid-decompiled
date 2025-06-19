package com.quizlet.db.data.orm.query;

import com.quizlet.db.data.models.base.DBModel;

/* loaded from: classes2.dex */
public class IdMappedQuery<M extends DBModel> extends BaseQuery<M> {
    public IdMappedQuery(BaseQuery baseQuery) {
        super(baseQuery.getModelType(), baseQuery.getFilters(), baseQuery.getIncludes());
    }
}
