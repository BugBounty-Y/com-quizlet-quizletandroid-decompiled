package androidx.compose.material3;

import androidx.compose.material3.internal.AbstractC0655t;
import androidx.compose.runtime.C0776c;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class J0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.compose.foundation.lazy.A k;
    public final /* synthetic */ Function1 l;
    public final /* synthetic */ AbstractC0655t m;
    public final /* synthetic */ IntRange n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public J0(androidx.compose.foundation.lazy.A a, Function1 function1, AbstractC0655t abstractC0655t, IntRange intRange, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = a;
        this.l = function1;
        this.m = abstractC0655t;
        this.n = intRange;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new J0(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((J0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            this.j = 1;
            float f = Z0.a;
            androidx.compose.foundation.lazy.A a = this.k;
            Object objB = C0776c.F(new androidx.compose.animation.core.K(a, 20)).b(new androidx.compose.foundation.K(a, this.l, this.m, this.n, 2), this);
            if (objB != aVar) {
                objB = Unit.a;
            }
            if (objB == aVar) {
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
