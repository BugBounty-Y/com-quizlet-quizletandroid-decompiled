package com.quizlet.infra.legacysyncengine.tasks.read;

import com.google.android.gms.internal.common.g;
import com.j256.ormlite.stmt.QueryBuilder;
import com.j256.ormlite.stmt.Where;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.orm.Filter;
import com.quizlet.db.data.orm.Include;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.internal.operators.single.k;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes3.dex */
public class b {
    public final ModelType a;
    public final DatabaseHelper b;
    public final o c;
    public final IdMappedQuery d;

    public b(IdMappedQuery idMappedQuery, DatabaseHelper databaseHelper, o oVar) {
        this.d = idMappedQuery;
        this.a = idMappedQuery.getModelType();
        this.b = databaseHelper;
        this.c = oVar;
    }

    public boolean a() {
        return false;
    }

    public void b(QueryBuilder queryBuilder) {
    }

    public Where c(QueryBuilder queryBuilder) throws SQLException {
        g it2 = this.d.getFilters().iterator();
        Where whereIn = null;
        while (it2.hasNext()) {
            Filter filter = (Filter) it2.next();
            whereIn = (whereIn != null ? whereIn.and() : queryBuilder.where()).in(filter.getField().getDatabaseColumnName(), filter.getFieldValues());
        }
        if (a()) {
            return whereIn;
        }
        return (whereIn != null ? whereIn.and() : queryBuilder.where()).eq("isDeleted", Boolean.FALSE);
    }

    public final List d(DatabaseHelper databaseHelper) throws SQLException {
        QueryBuilder queryBuilder = this.b.j(this.a).queryBuilder();
        b(queryBuilder);
        Where whereC = c(queryBuilder);
        if (whereC == null) {
            whereC = queryBuilder.where();
        }
        List listQuery = whereC.query();
        if (listQuery == null) {
            return new ArrayList();
        }
        boolean zA = a();
        databaseHelper.getClass();
        IdMappedQuery idMappedQuery = this.d;
        if (idMappedQuery != null && idMappedQuery.getIncludes() != null && !idMappedQuery.getIncludes().isEmpty()) {
            Iterator<Include> it2 = idMappedQuery.getIncludes().iterator();
            while (it2.hasNext()) {
                databaseHelper.l(listQuery, it2.next().getRelationships(), zA);
            }
        }
        return listQuery;
    }

    public i e() {
        return new com.jakewharton.rxbinding4.a(new a(this, 1), 4).w(this.c);
    }

    public final k f() {
        return new io.reactivex.rxjava3.internal.operators.flowable.b(new a(this, 0), 4).l(this.c);
    }
}
