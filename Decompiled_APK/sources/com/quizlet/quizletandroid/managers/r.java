package com.quizlet.quizletandroid.managers;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import java.sql.SQLException;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ u j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(u uVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new r(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        u uVar = this.j;
        uVar.getClass();
        boolean z = false;
        try {
            List listQuery = uVar.b.r(Models.STUDY_SET, false).lt(DBStudySetFields.ID.getDatabaseColumnName(), 0).query();
            Intrinsics.checkNotNullExpressionValue(listQuery, "query(...)");
            z = !listQuery.isEmpty();
        } catch (SQLException e) {
            timber.log.c.a.e(e);
        }
        return Boolean.valueOf(z);
    }
}
