package com.quizlet.edgy.ui.fragment;

import androidx.fragment.app.AbstractC1136h0;
import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class L extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ EdgyModalFragment k;
    public final /* synthetic */ AbstractC1136h0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(AbstractC1136h0 abstractC1136h0, EdgyModalFragment edgyModalFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = edgyModalFragment;
        this.l = abstractC1136h0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new L(this.l, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((L) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            EdgyModalFragment edgyModalFragment = this.k;
            androidx.lifecycle.J viewLifecycleOwner = edgyModalFragment.getViewLifecycleOwner();
            Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            K k = new K(this.l, edgyModalFragment, null);
            this.j = 1;
            if (p0.m(viewLifecycleOwner, b, k, this) == aVar) {
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
