package androidx.compose.material3;

import androidx.compose.material3.internal.C0657v;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class A0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.compose.foundation.lazy.A k;
    public final /* synthetic */ int l;
    public final /* synthetic */ IntRange m;
    public final /* synthetic */ C0657v n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A0(androidx.compose.foundation.lazy.A a, int i, IntRange intRange, C0657v c0657v, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = a;
        this.l = i;
        this.m = intRange;
        this.n = c0657v;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new A0(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((A0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            int i2 = (((this.l - this.m.a) * 12) + this.n.b) - 1;
            this.j = 1;
            if (androidx.compose.foundation.lazy.A.j(this.k, i2, this) == aVar) {
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
