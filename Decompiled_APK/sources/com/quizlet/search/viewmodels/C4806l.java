package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;

/* renamed from: com.quizlet.search.viewmodels.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4806l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ p k;
    public final /* synthetic */ com.quizlet.ui.models.search.c l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4806l(p pVar, com.quizlet.ui.models.search.c cVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = pVar;
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4806l(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4806l) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            p pVar = this.k;
            com.quizlet.search.logging.a aVar2 = pVar.h;
            com.quizlet.ui.models.search.c cVar = this.l;
            com.quizlet.data.model.search.c banner = cVar.a;
            aVar2.getClass();
            Intrinsics.checkNotNullParameter(banner, "banner");
            aVar2.a(banner, "search_banner_clicked");
            d0 d0Var = pVar.j;
            com.quizlet.search.navigation.c cVar2 = new com.quizlet.search.navigation.c(new com.quizlet.ui.models.webpage.k(cVar.a));
            this.j = 1;
            if (d0Var.emit(cVar2, this) == aVar) {
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
