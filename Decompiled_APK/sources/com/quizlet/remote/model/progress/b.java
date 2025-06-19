package com.quizlet.remote.model.progress;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.progress.ProgressResetResponse;
import io.reactivex.rxjava3.functions.h;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements h {
    public static final b a = new b();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        ProgressResetResponse.Models models;
        List list;
        ApiThreeWrapper it2 = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        ProgressResetResponse progressResetResponse = (ProgressResetResponse) it2.a();
        return (progressResetResponse == null || (models = progressResetResponse.d) == null || (list = models.a) == null) ? K.a : list;
    }
}
