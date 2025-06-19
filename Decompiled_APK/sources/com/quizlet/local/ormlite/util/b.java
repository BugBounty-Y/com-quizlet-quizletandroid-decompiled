package com.quizlet.local.ormlite.util;

import com.j256.ormlite.dao.Dao;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class b {
    public static final io.reactivex.rxjava3.internal.operators.completable.c a(Dao dao, List models) {
        Intrinsics.checkNotNullParameter(dao, "<this>");
        Intrinsics.checkNotNullParameter(models, "models");
        Intrinsics.checkNotNullParameter(dao, "<this>");
        Intrinsics.checkNotNullParameter(models, "models");
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new com.google.firebase.tracing.a(21, dao, models), 3);
        Intrinsics.checkNotNullExpressionValue(bVar, "create(...)");
        io.reactivex.rxjava3.internal.operators.completable.c cVar = new io.reactivex.rxjava3.internal.operators.completable.c(bVar, 6);
        Intrinsics.checkNotNullExpressionValue(cVar, "ignoreElement(...)");
        return cVar;
    }

    public static final io.reactivex.rxjava3.internal.operators.flowable.b b(Dao dao, String query) {
        Intrinsics.checkNotNullParameter(dao, "<this>");
        Intrinsics.checkNotNullParameter(query, "query");
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new a(dao, query, 0), 3);
        Intrinsics.checkNotNullExpressionValue(bVar, "create(...)");
        return bVar;
    }

    public static final io.reactivex.rxjava3.internal.operators.completable.c c(Dao dao, String statement) {
        Intrinsics.checkNotNullParameter(dao, "<this>");
        Intrinsics.checkNotNullParameter(statement, "statement");
        Intrinsics.checkNotNullParameter(dao, "<this>");
        Intrinsics.checkNotNullParameter(statement, "statement");
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new a(dao, statement, 1), 3);
        Intrinsics.checkNotNullExpressionValue(bVar, "create(...)");
        io.reactivex.rxjava3.internal.operators.completable.c cVar = new io.reactivex.rxjava3.internal.operators.completable.c(bVar, 6);
        Intrinsics.checkNotNullExpressionValue(cVar, "ignoreElement(...)");
        return cVar;
    }
}
