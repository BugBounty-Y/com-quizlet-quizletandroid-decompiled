package com.quizlet.quizletandroid.ui.setpage.terms;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public int j;
    public final /* synthetic */ TermListFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(TermListFragment termListFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = termListFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            String str = TermListFragment.H;
            TermListFragment termListFragment = this.k;
            s0 s0Var = ((com.quizlet.features.setpage.terms.viewmodel.c) termListFragment.F.getValue()).h;
            d dVar = new d(termListFragment, null);
            this.j = 1;
            if (e0.i(s0Var, dVar, this) == aVar) {
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
