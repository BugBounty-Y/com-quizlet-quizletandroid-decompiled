package com.quizlet.data.interactor.progress;

import com.quizlet.data.model.I0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements io.reactivex.rxjava3.functions.d {
    public static final b a = new b();

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        I0 it2 = (I0) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        c.e = System.currentTimeMillis();
    }
}
