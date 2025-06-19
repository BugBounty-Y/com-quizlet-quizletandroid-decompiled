package com.quizlet.features.setpage.offline;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements io.reactivex.rxjava3.functions.h {
    public static final d a = new d();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        Boolean it2 = (Boolean) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return it2.booleanValue() ? com.quizlet.features.infra.models.b.c : com.quizlet.features.infra.models.b.d;
    }
}
