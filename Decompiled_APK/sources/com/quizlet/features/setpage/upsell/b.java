package com.quizlet.features.setpage.upsell;

import io.reactivex.rxjava3.functions.h;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements h {
    public static final b a = new b();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        Integer it2 = (Integer) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return Boolean.valueOf(it2.intValue() != 1);
    }
}
