package com.quizlet.quizletandroid.ui.group.addclassset.viewmodel;

import com.quizlet.data.repository.set.f;
import com.quizlet.infra.legacysyncengine.datasources.h;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class b extends com.quizlet.quizletandroid.ui.base.viewmodel.a {
    /* JADX WARN: Illegal instructions before constructor call */
    public b(f dataSourceProvider) {
        Intrinsics.checkNotNullParameter(dataSourceProvider, "dataSourceProvider");
        h hVar = (h) dataSourceProvider.b;
        Intrinsics.checkNotNullExpressionValue(hVar, "getSetsDataSource(...)");
        super(hVar);
    }
}
