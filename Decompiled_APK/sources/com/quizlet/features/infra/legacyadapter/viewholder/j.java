package com.quizlet.features.infra.legacyadapter.viewholder;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j implements io.reactivex.rxjava3.functions.h {
    public static final j a = new j();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        Boolean it2 = (Boolean) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return Boolean.valueOf(!it2.booleanValue());
    }
}
