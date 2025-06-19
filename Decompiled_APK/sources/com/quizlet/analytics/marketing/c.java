package com.quizlet.analytics.marketing;

import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c implements h, i {
    public static final c a = new c();
    public static final c b = new c();

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Boolean it2 = (Boolean) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return Boolean.valueOf(!it2.booleanValue());
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        Boolean it2 = (Boolean) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return it2.booleanValue();
    }
}
