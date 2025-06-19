package androidx.compose.animation.core;

import androidx.compose.runtime.C0776c;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class B0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public float j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ E0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B0(E0 e0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = e0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        B0 b0 = new B0(this.m, hVar);
        b0.l = obj;
        return b0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((B0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        float fN;
        kotlinx.coroutines.C c;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            kotlinx.coroutines.C c2 = (kotlinx.coroutines.C) this.l;
            fN = AbstractC0240f.n(c2.getCoroutineContext());
            c = c2;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            fN = this.j;
            c = (kotlinx.coroutines.C) this.l;
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        while (kotlinx.coroutines.E.x(c)) {
            A0 a0 = new A0(this.m, fN);
            this.l = c;
            this.j = fN;
            this.k = 1;
            if (C0776c.r(getContext()).P(a0, this) == aVar) {
                return aVar;
            }
        }
        return Unit.a;
    }
}
