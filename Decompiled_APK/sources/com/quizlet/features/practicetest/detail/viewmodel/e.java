package com.quizlet.features.practicetest.detail.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.features.practicetest.detail.data.q;
import com.quizlet.features.practicetest.detail.data.y;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ i j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(i iVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        i iVar = this.j;
        boolean zB = Intrinsics.b((Boolean) iVar.b.a("question_bank_private"), Boolean.TRUE);
        d0 d0Var = iVar.k;
        if (zB) {
            d0Var.h(q.a);
        } else {
            iVar.c.getClass();
            String questionBankUuid = iVar.m;
            Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
            String str = "https://quizlet.com/test-questions/" + questionBankUuid;
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            d0Var.h(new y(new com.quizlet.features.infra.models.share.a(str, "practice-test-page-share", new com.quizlet.qutils.string.f(R.string.share_question_bank, C4933y.P(args)), new C4237k(28), new C4237k(29))));
        }
        return Unit.a;
    }
}
