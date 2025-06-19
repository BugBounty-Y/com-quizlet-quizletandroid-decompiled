package com.quizlet.uicommon.ui.common.overflowmenu;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ FullscreenOverflowFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(FullscreenOverflowFragment fullscreenOverflowFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = fullscreenOverflowFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            FullscreenOverflowFragment fullscreenOverflowFragment = this.k;
            s0 s0Var = ((i) fullscreenOverflowFragment.r.getValue()).b;
            a aVar2 = fullscreenOverflowFragment.s;
            if (aVar2 == null) {
                Intrinsics.m("adapter");
                throw null;
            }
            androidx.compose.runtime.internal.c cVar = new androidx.compose.runtime.internal.c(2, aVar2, a.class, "submitList", "submitList(Ljava/util/List;)V", 4, 18);
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
