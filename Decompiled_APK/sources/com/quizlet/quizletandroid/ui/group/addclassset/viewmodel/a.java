package com.quizlet.quizletandroid.ui.group.addclassset.viewmodel;

import com.quizlet.data.repository.set.f;
import com.quizlet.infra.legacysyncengine.datasources.p;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class a extends com.quizlet.quizletandroid.ui.base.viewmodel.a {
    /* JADX WARN: Illegal instructions before constructor call */
    public a(f dataSourceProvider) {
        Intrinsics.checkNotNullParameter(dataSourceProvider, "dataSourceProvider");
        p pVar = (p) dataSourceProvider.c;
        Intrinsics.checkNotNullExpressionValue(pVar, "getClassSetsDataSource(...)");
        super(pVar);
    }
}
