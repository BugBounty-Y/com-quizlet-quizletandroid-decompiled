package com.quizlet.search.viewmodels;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

@Metadata
/* loaded from: classes3.dex */
public final class p extends w0 {
    public final com.quizlet.data.repository.searchexplanations.c b;
    public final com.quizlet.search.logging.b c;
    public final ExplanationsLogger d;
    public final com.quizlet.features.emailconfirmation.logging.a e;
    public final SearchEventLogger f;
    public final com.google.firebase.messaging.p g;
    public final com.quizlet.search.logging.a h;
    public final s0 i;
    public final d0 j;
    public final Y k;
    public final C4203d l;
    public y0 m;
    public String n;

    public p(com.quizlet.data.repository.searchexplanations.c getTypeAheadSuggestionsUseCase, com.quizlet.search.logging.b typeAheadEventLogger, ExplanationsLogger explanationsEventLogger, com.quizlet.features.emailconfirmation.logging.a quizletLiveLogger, SearchEventLogger searchEventLogger, com.google.firebase.messaging.p getQueryMisspellingsUseCase, long j, com.quizlet.search.logging.a searchBannerEventLogger) {
        Intrinsics.checkNotNullParameter(getTypeAheadSuggestionsUseCase, "getTypeAheadSuggestionsUseCase");
        Intrinsics.checkNotNullParameter(typeAheadEventLogger, "typeAheadEventLogger");
        Intrinsics.checkNotNullParameter(explanationsEventLogger, "explanationsEventLogger");
        Intrinsics.checkNotNullParameter(quizletLiveLogger, "quizletLiveLogger");
        Intrinsics.checkNotNullParameter(searchEventLogger, "searchEventLogger");
        Intrinsics.checkNotNullParameter(getQueryMisspellingsUseCase, "getQueryMisspellingsUseCase");
        Intrinsics.checkNotNullParameter(searchBannerEventLogger, "searchBannerEventLogger");
        this.b = getTypeAheadSuggestionsUseCase;
        this.c = typeAheadEventLogger;
        this.d = explanationsEventLogger;
        this.e = quizletLiveLogger;
        this.f = searchEventLogger;
        this.g = getQueryMisspellingsUseCase;
        this.h = searchBannerEventLogger;
        this.i = e0.c(com.quizlet.search.data.e.a);
        d0 d0VarB = e0.b(0, 0, null, 7);
        this.j = d0VarB;
        this.k = new Y(d0VarB);
        this.l = new C4203d(this);
        this.n = "";
        searchEventLogger.setUserId(Long.valueOf(j));
    }

    public static void A(p pVar, int i) {
        com.quizlet.search.navigation.e eVar = com.quizlet.search.navigation.e.b;
        if ((i & 1) != 0) {
            eVar = com.quizlet.search.navigation.e.a;
        }
        pVar.getClass();
        kotlinx.coroutines.E.A(p0.j(pVar), null, null, new C4798d(pVar, eVar, null, null), 3);
    }

    public final void B(String query, boolean z) {
        Intrinsics.checkNotNullParameter(query, "query");
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C4807m(this, z, query, null), 3);
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        this.f.D();
    }
}
