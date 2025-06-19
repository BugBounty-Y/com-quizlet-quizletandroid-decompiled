package com.quizlet.infra.legacysyncengine.tasks.read.sync;

import com.j256.ormlite.stmt.QueryBuilder;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.RelationshipGraph;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import com.quizlet.infra.legacysyncengine.tasks.read.c;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.o;

/* loaded from: classes3.dex */
public final class a extends c {
    public final /* synthetic */ int f = 1;

    public /* synthetic */ a(ModelType modelType, DatabaseHelper databaseHelper, RelationshipGraph relationshipGraph, o oVar) {
        super(modelType, databaseHelper, relationshipGraph, oVar);
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.read.c, com.quizlet.infra.legacysyncengine.tasks.read.b
    public void b(QueryBuilder queryBuilder) {
        switch (this.f) {
            case 1:
                queryBuilder.orderBy(DBTermFields.RANK.getDatabaseColumnName(), true);
                queryBuilder.orderBy(DBTermFields.ID.getDatabaseColumnName(), false);
                queryBuilder.orderBy("localGeneratedId", false);
                break;
            default:
                super.b(queryBuilder);
                break;
        }
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.read.b
    public i e() {
        switch (this.f) {
            case 0:
                return super.e().l(new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 1));
            default:
                return super.e();
        }
    }

    public /* synthetic */ a(IdMappedQuery idMappedQuery, DatabaseHelper databaseHelper, RelationshipGraph relationshipGraph, o oVar) {
        super(idMappedQuery, databaseHelper, relationshipGraph, oVar);
    }
}
