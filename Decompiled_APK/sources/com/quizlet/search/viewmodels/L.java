package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes3.dex */
public final class L extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ M k;
    public final /* synthetic */ long l;
    public final /* synthetic */ long m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(M m, long j, long j2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = m;
        this.l = j;
        this.m = j2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new L(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((L) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            M m = this.k;
            SearchEventLogger searchEventLogger = m.d;
            long j = this.l;
            long j2 = this.m;
            searchEventLogger.f(j, j2);
            m.i = false;
            d0 d0Var = m.g;
            com.quizlet.search.data.term.c cVar = new com.quizlet.search.data.term.c(j2);
            this.j = 1;
            if (d0Var.emit(cVar, this) == aVar) {
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
