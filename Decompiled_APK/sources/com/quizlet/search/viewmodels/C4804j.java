package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.d0;

/* renamed from: com.quizlet.search.viewmodels.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4804j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ p k;
    public final /* synthetic */ long l;
    public final /* synthetic */ int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4804j(p pVar, long j, int i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = pVar;
        this.l = j;
        this.m = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4804j(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4804j) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            p pVar = this.k;
            SearchEventLogger searchEventLogger = pVar.f;
            long j = this.l;
            searchEventLogger.A(this.m, j);
            d0 d0Var = pVar.j;
            com.quizlet.search.navigation.k kVar = new com.quizlet.search.navigation.k(j);
            this.j = 1;
            if (d0Var.emit(kVar, this) == aVar) {
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
