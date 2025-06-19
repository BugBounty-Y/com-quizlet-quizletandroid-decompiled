package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.B1;
import com.quizlet.data.model.C1;
import com.quizlet.eventlogger.features.search.SearchEventsEventLog;
import com.quizlet.generated.enums.EnumC4466a1;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ p k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(p pVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = pVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new n(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object objI;
        s0 s0Var;
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        String query = this.l;
        p pVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.repository.searchexplanations.c cVar = pVar.b;
            this.j = 1;
            objI = cVar.i(query, this);
            if (objI == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objI = obj;
        }
        C1 suggestionData = (C1) objI;
        com.quizlet.search.logging.b bVar = pVar.c;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(query, "query");
        Intrinsics.checkNotNullParameter(suggestionData, "suggestionData");
        bVar.b = new com.quizlet.search.data.d(suggestionData.a, query);
        int length = query.length();
        List<B1> list = suggestionData.b;
        if (length != 0) {
            SearchEventsEventLog searchEventsEventLogA = SearchEventsEventLog.Companion.a(SearchEventsEventLog.b, bVar.b.a, (list.isEmpty() ? EnumC4466a1.TYPEAHEAD_FETCHED_SUGGESTIONS_NO_RESULTS : EnumC4466a1.TYPEAHEAD_FETCHED_SUGGESTIONS_WITH_RESULTS).a(), bVar.b.b, null, null, null, null, null, null, null, null, null, null, 16376);
            searchEventsEventLogA.getPayload().setSuggestions(list);
            bVar.a.l(searchEventsEventLogA);
        }
        do {
            s0Var = pVar.i;
            value = s0Var.getValue();
        } while (!s0Var.k(value, !list.isEmpty() ? new com.quizlet.search.data.h(query, list) : com.quizlet.search.data.g.a));
        return Unit.a;
    }
}
