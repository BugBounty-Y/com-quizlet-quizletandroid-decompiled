package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class s extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ int j;
    public final /* synthetic */ t k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(int i, t tVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = i;
        this.k = tVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new s(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((s) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.quizletandroid.ui.studymodes.testmode.models.h hVar = this.j <= 80 ? new com.quizlet.quizletandroid.ui.studymodes.testmode.models.h(R.string.you_are_learning, new Integer(R.string.results_description), new Integer(R.drawable.ic_comp_learn_flex_lightbulb), 8) : new com.quizlet.quizletandroid.ui.studymodes.testmode.models.h(R.string.you_know_your_stuff, null, new Integer(2131231363), 10);
        s0 s0Var = this.k.f;
        do {
            value = s0Var.getValue();
        } while (!s0Var.k(value, new C4759a(kotlin.collections.A.b(hVar))));
        return Unit.a;
    }
}
