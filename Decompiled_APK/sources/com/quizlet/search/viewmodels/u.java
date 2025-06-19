package com.quizlet.search.viewmodels;

import androidx.compose.material3.C0676l1;
import androidx.lifecycle.p0;
import androidx.paging.AbstractC1348x;
import androidx.paging.C1347w0;
import androidx.paging.V;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.search.SearchType;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.Y;

@Metadata
/* loaded from: classes3.dex */
public final class u extends AbstractC4797c {
    public final com.google.mlkit.vision.documentscanner.internal.c h;
    public final com.quizlet.data.repository.achievements.h i;
    public final com.quizlet.quizletandroid.ui.common.images.capture.a j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(com.google.mlkit.vision.documentscanner.internal.c searchClassUseCase, com.quizlet.data.repository.achievements.h searchAdsManager, com.quizlet.quizletandroid.ui.common.images.capture.a searchUiMapper, SearchEventLogger searchEventLogger) {
        super(searchEventLogger);
        Intrinsics.checkNotNullParameter(searchClassUseCase, "searchClassUseCase");
        Intrinsics.checkNotNullParameter(searchAdsManager, "searchAdsManager");
        Intrinsics.checkNotNullParameter(searchUiMapper, "searchUiMapper");
        Intrinsics.checkNotNullParameter(searchEventLogger, "searchEventLogger");
        this.h = searchClassUseCase;
        this.i = searchAdsManager;
        this.j = searchUiMapper;
    }

    @Override // com.quizlet.search.viewmodels.AbstractC4797c
    public final SearchType A() {
        return SearchType.c;
    }

    @Override // com.quizlet.search.viewmodels.AbstractC4797c
    public final Y B(String query) {
        Intrinsics.checkNotNullParameter(query, "query");
        C0676l1 config = new C0676l1(20, 62);
        com.quizlet.search.composables.o pagingSourceFactory = new com.quizlet.search.composables.o(this, query, 1);
        Intrinsics.checkNotNullParameter(config, "config");
        Intrinsics.checkNotNullParameter(pagingSourceFactory, "pagingSourceFactory");
        Intrinsics.checkNotNullParameter(config, "config");
        Intrinsics.checkNotNullParameter(pagingSourceFactory, "pagingSourceFactory");
        return AbstractC1348x.b(new androidx.compose.material3.internal.H(13, new V(new C1347w0(pagingSourceFactory, null), config).e, this), p0.j(this));
    }
}
