package com.quizlet.remote.model.set;

import com.quizlet.data.model.C4161r0;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.set.IrrelevantRecommendationsResponse;
import io.reactivex.rxjava3.functions.h;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements h {
    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        IrrelevantRecommendationsResponse.Models models;
        List list;
        ApiThreeWrapper response = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        IrrelevantRecommendationsResponse irrelevantRecommendationsResponse = (IrrelevantRecommendationsResponse) response.a();
        RemoteIrrelevantRecommendation remote = (irrelevantRecommendationsResponse == null || (models = irrelevantRecommendationsResponse.d) == null || (list = models.a) == null) ? null : (RemoteIrrelevantRecommendation) CollectionsKt.L(list);
        Intrinsics.d(remote);
        Intrinsics.checkNotNullParameter(remote, "remote");
        return new C4161r0(remote.b, remote.c, remote.d, remote.a);
    }
}
