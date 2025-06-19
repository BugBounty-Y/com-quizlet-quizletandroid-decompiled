package com.quizlet.infra.legacysyncengine.tasks.read.sync;

import com.j256.ormlite.stmt.QueryBuilder;
import com.j256.ormlite.stmt.Where;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.infra.legacysyncengine.tasks.read.c;
import java.sql.SQLException;

/* loaded from: classes3.dex */
public final class b extends c {
    @Override // com.quizlet.infra.legacysyncengine.tasks.read.c, com.quizlet.infra.legacysyncengine.tasks.read.b
    public final Where c(QueryBuilder queryBuilder) throws SQLException {
        Where whereC = super.c(queryBuilder);
        Boolean bool = Boolean.TRUE;
        whereC.and(whereC, whereC.or(whereC.eq("isDeleted", bool), whereC.eq(DBStudySetFields.Names.READY_TO_CREATE, bool), whereC.ge(DBStudySetFields.ID.getDatabaseColumnName(), 0)));
        return whereC;
    }
}
