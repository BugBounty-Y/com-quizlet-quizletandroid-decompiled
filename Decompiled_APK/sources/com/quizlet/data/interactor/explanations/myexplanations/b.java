package com.quizlet.data.interactor.explanations.myexplanations;

import io.reactivex.rxjava3.functions.h;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements h {
    public static final b a = new b();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        List it2 = (List) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return CollectionsKt.n0(it2, new a());
    }
}
