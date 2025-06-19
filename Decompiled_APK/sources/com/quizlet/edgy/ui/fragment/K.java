package com.quizlet.edgy.ui.fragment;

import androidx.fragment.app.AbstractC1136h0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes2.dex */
public final class K extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ EdgyModalFragment k;
    public final /* synthetic */ AbstractC1136h0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(AbstractC1136h0 abstractC1136h0, EdgyModalFragment edgyModalFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = edgyModalFragment;
        this.l = abstractC1136h0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new K(this.l, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((K) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            String str = EdgyModalFragment.L;
            EdgyModalFragment edgyModalFragment = this.k;
            Y y = ((com.quizlet.edgy.ui.viewmodel.M) edgyModalFragment.K.getValue()).r;
            J j = new J(this.l, edgyModalFragment, null);
            this.j = 1;
            if (e0.i(y, j, this) == aVar) {
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
