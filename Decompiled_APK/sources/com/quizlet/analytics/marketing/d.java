package com.quizlet.analytics.marketing;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d implements io.reactivex.rxjava3.functions.d {
    public static final d a = new d();

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        Boolean it2 = (Boolean) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        com.quizlet.data.repository.classfolder.e.e = it2;
    }
}
