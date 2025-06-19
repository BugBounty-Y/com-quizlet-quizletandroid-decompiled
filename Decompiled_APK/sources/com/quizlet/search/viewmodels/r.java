package com.quizlet.search.viewmodels;

import androidx.lifecycle.w0;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.search.SearchType;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class r extends w0 {
    public final com.quizlet.data.repository.folderwithcreatorinclass.e b;
    public final SearchEventLogger c;
    public final SearchType d;
    public final s0 e;
    public String f;
    public boolean g;
    public boolean h;
    public final C4203d i;

    public r(com.quizlet.data.repository.folderwithcreatorinclass.e searchAllResultsDataSource, SearchEventLogger searchEventLogger) {
        Intrinsics.checkNotNullParameter(searchAllResultsDataSource, "searchAllResultsDataSource");
        Intrinsics.checkNotNullParameter(searchEventLogger, "searchEventLogger");
        this.b = searchAllResultsDataSource;
        this.c = searchEventLogger;
        this.d = SearchType.a;
        this.e = e0.c(com.quizlet.search.data.blended.g.a);
        this.f = "";
        this.i = new C4203d(this);
    }
}
