package com.quizlet.search.viewmodels;

import androidx.compose.material3.C0676l1;
import androidx.lifecycle.p0;
import androidx.paging.AbstractC1348x;
import androidx.paging.C1347w0;
import androidx.paging.V;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.search.SearchType;
import com.quizlet.search.data.SearchFilterContentTypeState;
import com.quizlet.search.data.SearchFilterCreatorTypeState;
import com.quizlet.search.data.SearchFilterNumTermsState;
import com.quizlet.search.data.SearchFiltersStates;
import java.util.LinkedHashSet;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class A extends AbstractC4797c {
    public final com.quizlet.data.interactor.studysetwithcreator.a h;
    public final com.quizlet.data.repository.achievements.h i;
    public final com.quizlet.quizletandroid.ui.common.images.capture.a j;
    public final SearchEventLogger k;
    public com.quizlet.search.paging.d l;
    public final LinkedHashSet m;
    public final s0 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(com.quizlet.data.interactor.studysetwithcreator.a searchStudySetWithCreatorUseCase, com.quizlet.data.repository.achievements.h searchAdsManager, com.quizlet.quizletandroid.ui.common.images.capture.a searchUiMapper, SearchEventLogger searchEventLogger) {
        super(searchEventLogger);
        Intrinsics.checkNotNullParameter(searchStudySetWithCreatorUseCase, "searchStudySetWithCreatorUseCase");
        Intrinsics.checkNotNullParameter(searchAdsManager, "searchAdsManager");
        Intrinsics.checkNotNullParameter(searchUiMapper, "searchUiMapper");
        Intrinsics.checkNotNullParameter(searchEventLogger, "searchEventLogger");
        this.h = searchStudySetWithCreatorUseCase;
        this.i = searchAdsManager;
        this.j = searchUiMapper;
        this.k = searchEventLogger;
        this.m = new LinkedHashSet();
        this.n = e0.c(new SearchFiltersStates(new SearchFilterNumTermsState(null), new SearchFilterCreatorTypeState(null), new SearchFilterContentTypeState(null)));
    }

    @Override // com.quizlet.search.viewmodels.AbstractC4797c
    public final SearchType A() {
        return SearchType.b;
    }

    @Override // com.quizlet.search.viewmodels.AbstractC4797c
    public final Y B(String query) {
        Intrinsics.checkNotNullParameter(query, "query");
        C0676l1 config = new C0676l1(25, 62);
        com.quizlet.search.composables.F pagingSourceFactory = new com.quizlet.search.composables.F(this, query, 1);
        Intrinsics.checkNotNullParameter(config, "config");
        Intrinsics.checkNotNullParameter(pagingSourceFactory, "pagingSourceFactory");
        Intrinsics.checkNotNullParameter(config, "config");
        Intrinsics.checkNotNullParameter(pagingSourceFactory, "pagingSourceFactory");
        return AbstractC1348x.b(new androidx.compose.material3.internal.H(15, new V(new C1347w0(pagingSourceFactory, null), config).e, this), p0.j(this));
    }
}
