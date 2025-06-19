package com.quizlet.ui.compose;

import androidx.compose.runtime.W0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.ui.compose.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4823p extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.compose.foundation.lazy.A k;
    public final /* synthetic */ float l;
    public final /* synthetic */ W0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4823p(androidx.compose.foundation.lazy.A a, float f, W0 w0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = a;
        this.l = f;
        this.m = w0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4823p(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4823p) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.compose.foundation.lazy.A a = this.k;
            long jA = a.h().a();
            int iIntValue = ((Number) this.m.getValue()).intValue();
            float f = this.l;
            this.j = 1;
            if (a.f(iIntValue, (int) ((f / 2) - (((int) (jA >> 32)) / 2)), this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
