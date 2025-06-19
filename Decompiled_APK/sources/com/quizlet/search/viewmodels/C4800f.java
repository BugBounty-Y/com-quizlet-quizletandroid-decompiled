package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;

/* renamed from: com.quizlet.search.viewmodels.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4800f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ p k;
    public final /* synthetic */ String l;
    public final /* synthetic */ int m;
    public final /* synthetic */ String n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4800f(p pVar, String str, int i, String str2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = pVar;
        this.l = str;
        this.m = i;
        this.n = str2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4800f(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4800f) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws NumberFormatException {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            p pVar = this.k;
            SearchEventLogger searchEventLogger = pVar.f;
            String str = this.l;
            long j = Long.parseLong(str);
            int i2 = this.m;
            searchEventLogger.C(i2, j);
            String query = pVar.n;
            ExplanationsLogger.EventData.Question eventData = new ExplanationsLogger.EventData.Question(str, this.n);
            ExplanationsLogger explanationsLogger = pVar.d;
            explanationsLogger.getClass();
            Intrinsics.checkNotNullParameter(query, "query");
            Intrinsics.checkNotNullParameter(eventData, "eventData");
            ExplanationsEventLog.Companion companion = ExplanationsEventLog.b;
            androidx.navigation.serialization.k kVar = new androidx.navigation.serialization.k(i2, eventData, explanationsLogger, query);
            companion.getClass();
            explanationsLogger.a(ExplanationsEventLog.Companion.a("search_result_tapped", kVar));
            d0 d0Var = pVar.j;
            com.quizlet.search.navigation.d dVar = new com.quizlet.search.navigation.d(str);
            this.j = 1;
            if (d0Var.emit(dVar, this) == aVar) {
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
