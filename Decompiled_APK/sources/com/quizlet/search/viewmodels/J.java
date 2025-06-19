package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3762x6;
import com.quizlet.search.data.term.TermSearchUiModel;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.flow.C4986c;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class J extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ M k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public J(M m, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = m;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new J(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((J) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            M m = this.k;
            com.quizlet.data.interactor.set.c cVar = m.c;
            TermSearchUiModel termSearchUiModel = m.e;
            InterfaceC4992i flow1 = e0.m(e0.s(K1.f(((com.quizlet.data.repository.user.e) cVar.a).e(termSearchUiModel.c)), (AbstractC5040y) cVar.c));
            long j = termSearchUiModel.b;
            com.quizlet.data.repository.term.g gVar = (com.quizlet.data.repository.term.g) m.b.b;
            io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.term.a(gVar, j, 5), 4);
            Intrinsics.checkNotNullExpressionValue(bVar, "defer(...)");
            io.reactivex.rxjava3.core.i iVarM = AbstractC3762x6.c(bVar, gVar.e, "Error retrieving terms from remote").m();
            Intrinsics.checkNotNullExpressionValue(iVarM, "toObservable(...)");
            C4986c flow2 = K1.f(iVarM);
            int i2 = com.quizlet.qutils.coroutines.c.a;
            Intrinsics.checkNotNullParameter(flow1, "flow1");
            Intrinsics.checkNotNullParameter(flow2, "flow2");
            com.quizlet.features.folders.addtofolder.viewmodel.usecase.c cVar2 = new com.quizlet.features.folders.addtofolder.viewmodel.usecase.c(flow1, flow2, new com.quizlet.qutils.coroutines.a(3, 0, null), 2);
            I i3 = new I(m, null);
            this.j = 1;
            if (e0.i(cVar2, i3, this) == aVar) {
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
