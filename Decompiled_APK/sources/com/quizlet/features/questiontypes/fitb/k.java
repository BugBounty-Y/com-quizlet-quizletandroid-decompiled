package com.quizlet.features.questiontypes.fitb;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.db.data.models.persisted.DBAnswer;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ m k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(m mVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Exception {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            m mVar = this.k;
            com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a aVar2 = mVar.b;
            DBAnswer dBAnswer = mVar.n;
            if (dBAnswer == null) {
                Intrinsics.m("answer");
                throw null;
            }
            List listC = aVar2.c(dBAnswer, mVar.f, mVar.e);
            DBAnswer dBAnswer2 = mVar.n;
            if (dBAnswer2 == null) {
                Intrinsics.m("answer");
                throw null;
            }
            com.quizlet.features.questiontypes.basequestion.g gVar = new com.quizlet.features.questiontypes.basequestion.g(new com.quizlet.features.questiontypes.basequestion.data.b(dBAnswer2, listC));
            d0 d0Var = mVar.l;
            this.j = 1;
            if (d0Var.emit(gVar, this) == aVar) {
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
