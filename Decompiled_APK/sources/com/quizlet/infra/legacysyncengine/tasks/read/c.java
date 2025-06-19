package com.quizlet.infra.legacysyncengine.tasks.read;

import com.j256.ormlite.stmt.QueryBuilder;
import com.j256.ormlite.stmt.Where;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.RelationshipGraph;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import io.reactivex.rxjava3.core.o;
import java.sql.SQLException;
import java.util.HashSet;

/* loaded from: classes3.dex */
public class c extends b {
    public final RelationshipGraph e;

    public c(IdMappedQuery idMappedQuery, DatabaseHelper databaseHelper, RelationshipGraph relationshipGraph, o oVar) {
        super(idMappedQuery, databaseHelper, oVar);
        this.e = relationshipGraph;
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.read.b
    public final boolean a() {
        return true;
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.read.b
    public void b(QueryBuilder queryBuilder) {
        queryBuilder.orderBy("localGeneratedId", false);
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.read.b
    public Where c(QueryBuilder queryBuilder) throws SQLException {
        Where whereC = super.c(queryBuilder);
        Where whereAnd = whereC != null ? whereC.and() : queryBuilder.where();
        whereAnd.eq("dirty", Boolean.TRUE);
        for (Relationship relationship : this.e.getToOneRelationships(this.a)) {
            String fromFieldName = relationship.getFromFieldName();
            if (relationship.isRequired()) {
                whereAnd.and(whereAnd, whereAnd.or(whereAnd.eq("isDeleted", Boolean.TRUE), whereAnd.and(whereAnd.gt(fromFieldName, 0), whereAnd.isNotNull(fromFieldName))));
            } else {
                whereAnd.and(whereAnd, whereAnd.or(whereAnd.eq("isDeleted", Boolean.TRUE), whereAnd.ge(fromFieldName, 0), whereAnd.isNull(fromFieldName)));
            }
        }
        return whereAnd;
    }

    public c(ModelType modelType, DatabaseHelper databaseHelper, RelationshipGraph relationshipGraph, o oVar) {
        HashSet hashSet = new HashSet();
        super(new IdMappedQuery(new com.quizlet.infra.legacysyncengine.orm.query.a(modelType, com.google.common.collect.o.n(hashSet), new HashSet(modelType.getAutomaticIncludes()))), databaseHelper, oVar);
        this.e = relationshipGraph;
    }
}
