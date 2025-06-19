package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.search.data.term.TermSearchUiModel;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes3.dex */
public final class o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ p k;
    public final /* synthetic */ TermSearchUiModel l;
    public final /* synthetic */ int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(p pVar, TermSearchUiModel termSearchUiModel, int i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = pVar;
        this.l = termSearchUiModel;
        this.m = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new o(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((o) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            p pVar = this.k;
            SearchEventLogger searchEventLogger = pVar.f;
            TermSearchUiModel termSearchUiModel = this.l;
            searchEventLogger.v(termSearchUiModel.a, termSearchUiModel.b, this.m);
            pVar.f.p(termSearchUiModel.a, termSearchUiModel.b, this.m);
            d0 d0Var = pVar.j;
            com.quizlet.search.navigation.i iVar = new com.quizlet.search.navigation.i(termSearchUiModel);
            this.j = 1;
            if (d0Var.emit(iVar, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
