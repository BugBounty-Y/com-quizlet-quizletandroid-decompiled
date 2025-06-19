package androidx.compose.foundation.lazy.layout;

import androidx.compose.animation.core.C0238e;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class A extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ E k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(E e, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new A(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((A) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        E e = this.k;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0238e c0238e = e.o;
            androidx.compose.ui.unit.h hVar = new androidx.compose.ui.unit.h(0L);
            this.j = 1;
            if (c0238e.f(hVar, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        int i2 = E.t;
        e.g(0L);
        e.f(false);
        return Unit.a;
    }
}
