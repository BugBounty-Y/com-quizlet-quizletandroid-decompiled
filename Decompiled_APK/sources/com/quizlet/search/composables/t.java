package com.quizlet.search.composables;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.foundation.pager.C0466e;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0466e k;
    public final /* synthetic */ com.quizlet.search.data.a l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(C0466e c0466e, com.quizlet.search.data.a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0466e;
        this.l = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new t(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            int iOrdinal = this.l.ordinal() + 1;
            this.j = 1;
            if (this.k.f(iOrdinal, AbstractC0240f.q(7, null), this) == aVar) {
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
