package com.quizlet.features.match.viewmodel;

import androidx.compose.foundation.text.input.internal.u;
import androidx.lifecycle.m0;
import com.quizlet.data.repository.metering.j;
import io.reactivex.rxjava3.subjects.r;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class h extends com.quizlet.viewmodel.b {
    public final com.quizlet.viewmodel.livedata.b c;

    public h(m0 savedStateHandle, u dataProviderFactory) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(dataProviderFactory, "dataProviderFactory");
        j jVarD = dataProviderFactory.d(savedStateHandle);
        com.quizlet.viewmodel.livedata.b bVar = new com.quizlet.viewmodel.livedata.b();
        this.c = bVar;
        bVar.n();
        io.reactivex.rxjava3.internal.operators.single.g gVarG = ((r) jVarD.d).g(new com.quizlet.data.interactor.course.a(jVarD, 12));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        io.reactivex.rxjava3.internal.observers.e eVarI = gVarG.i(new com.quizlet.analytics.marketing.e(this, 9), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        Intrinsics.checkNotNullParameter(eVarI, "<this>");
        A(eVarI);
    }
}
