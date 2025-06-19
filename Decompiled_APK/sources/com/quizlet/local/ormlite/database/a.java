package com.quizlet.local.ormlite.database;

import com.quizlet.data.model.C4116c1;
import com.quizlet.data.model.Q;
import io.reactivex.rxjava3.functions.h;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public static final a a = new a();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        List it2 = (List) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        Object objFirstOrNull = CollectionsKt.firstOrNull(it2);
        return objFirstOrNull == null ? Q.a : new C4116c1(objFirstOrNull);
    }
}
