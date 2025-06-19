package com.quizlet.quizletandroid.ui.preview.viewmodel;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import com.braze.C1510p;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import io.reactivex.rxjava3.internal.operators.single.j;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class g extends com.quizlet.viewmodel.b {
    public final m0 c;
    public final com.quizlet.quizletandroid.ui.preview.dataclass.g d;
    public final SearchEventLogger e;
    public final Y f;
    public final X g;
    public final X h;
    public final X i;

    public g(m0 savedStateHandle, com.quizlet.quizletandroid.ui.preview.dataclass.g setPreviewOnboardingState, com.quizlet.data.repository.activitycenter.b factory, SearchEventLogger searchEventLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(setPreviewOnboardingState, "setPreviewOnboardingState");
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(searchEventLogger, "searchEventLogger");
        this.c = savedStateHandle;
        this.d = setPreviewOnboardingState;
        this.e = searchEventLogger;
        this.f = new Y();
        this.g = new X(1);
        this.h = new X(1);
        this.i = new X(1);
        Object objA = savedStateHandle.a("id");
        Intrinsics.e(objA, "null cannot be cast to non-null type kotlin.Long");
        Object objA2 = savedStateHandle.a("setIds");
        Intrinsics.e(objA2, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Long>");
        List list = (List) objA2;
        int iIndexOf = list.indexOf((Long) objA);
        int i = iIndexOf - 3;
        int iMin = Math.min((3 - (iIndexOf - Math.max(i, 0))) + iIndexOf + 3, B.i(list));
        List listSetId = list.subList(Math.max(i - (3 - (iMin - iIndexOf)), 0), iMin + 1);
        Object objA3 = savedStateHandle.a("id");
        Intrinsics.e(objA3, "null cannot be cast to non-null type kotlin.Long");
        int iIndexOf2 = listSetId.indexOf((Long) objA3);
        Intrinsics.checkNotNullParameter(listSetId, "listSetId");
        androidx.work.impl.model.e eVar = (androidx.work.impl.model.e) factory.c;
        io.ktor.client.plugins.api.d dVar = (io.ktor.client.plugins.api.d) factory.b;
        ArrayList arrayList = new ArrayList(C.q(listSetId, 10));
        Iterator it2 = listSetId.iterator();
        while (it2.hasNext()) {
            long jLongValue = ((Number) it2.next()).longValue();
            j stopToken = j.a;
            Intrinsics.checkNotNullExpressionValue(stopToken, "never(...)");
            C4885d c4885dJ = dVar.o(jLongValue, stopToken).j();
            Intrinsics.checkNotNullExpressionValue(stopToken, "never(...)");
            Intrinsics.checkNotNullParameter(stopToken, "stopToken");
            arrayList.add(p.p(c4885dJ, ((androidx.work.impl.model.c) eVar.c).c(stopToken, new C1510p(eVar, jLongValue, 9)), com.quizlet.quizletandroid.ui.preview.dataclass.b.a));
        }
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(arrayList, 8);
        Intrinsics.checkNotNullExpressionValue(bVar, "zip(...)");
        io.reactivex.rxjava3.internal.observers.e eVarI = new io.reactivex.rxjava3.internal.operators.single.d(bVar, new e(this, 0), 1).i(new f(this, iIndexOf2), new e(this, 1));
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        Intrinsics.checkNotNullParameter(eVarI, "<this>");
        A(eVarI);
    }
}
