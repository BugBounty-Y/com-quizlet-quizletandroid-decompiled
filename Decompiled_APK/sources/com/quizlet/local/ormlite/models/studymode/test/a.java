package com.quizlet.local.ormlite.models.studymode.test;

import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.model.v;
import com.j256.ormlite.stmt.QueryBuilder;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public final /* synthetic */ v j;
    public final /* synthetic */ long k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(v vVar, long j, boolean z, h hVar) {
        super(2, hVar);
        this.j = vVar;
        this.k = j;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        QueryBuilder queryBuilder = ((DatabaseHelper) this.j.b).i(Models.SESSION).queryBuilder();
        Intrinsics.checkNotNullExpressionValue(queryBuilder, "queryBuilder(...)");
        ModelField<DBSession, Long> modelField = DBSessionFields.ENDED_TIMESTAMP;
        DBSession dBSession = (DBSession) queryBuilder.orderBy(modelField.getDatabaseColumnName(), false).where().eq(DBSessionFields.STUDYABLE.getDatabaseColumnName(), new Long(this.k)).and().eq(DBSessionFields.ITEM_TYPE.getDatabaseColumnName(), new Integer(G1.SET.b())).and().eq(DBSessionFields.Names.SELECTED_TERMS_ONLY, Boolean.valueOf(this.l)).and().eq(DBSessionFields.MODE_TYPE.getDatabaseColumnName(), new Integer(A1.TEST.a())).and().gt(modelField.getDatabaseColumnName(), new Integer(0)).queryForFirst();
        if (dBSession != null) {
            return new Integer((int) dBSession.getScore());
        }
        return null;
    }
}
