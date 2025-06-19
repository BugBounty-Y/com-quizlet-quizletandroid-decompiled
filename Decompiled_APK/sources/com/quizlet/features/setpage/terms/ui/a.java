package com.quizlet.features.setpage.terms.ui;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ SelectedTermsModeFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(SelectedTermsModeFragment selectedTermsModeFragment, h hVar) {
        super(2, hVar);
        this.k = selectedTermsModeFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            SelectedTermsModeFragment selectedTermsModeFragment = this.k;
            s0 s0Var = ((com.quizlet.features.setpage.viewmodel.selectedtermsmode.b) selectedTermsModeFragment.j.getValue()).g;
            androidx.compose.runtime.internal.c cVar = new androidx.compose.runtime.internal.c(2, selectedTermsModeFragment, SelectedTermsModeFragment.class, "updateSelectorState", "updateSelectorState(Lcom/quizlet/features/setpage/terms/SelectedTermsModeState;)V", 4, 5);
            this.j = 1;
            if (e0.i(s0Var, cVar, this) == aVar) {
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
