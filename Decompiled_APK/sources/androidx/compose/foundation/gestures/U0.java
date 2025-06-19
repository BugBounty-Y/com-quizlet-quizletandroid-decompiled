package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class U0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ androidx.compose.ui.input.pointer.B l;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i m;
    public final /* synthetic */ kotlin.jvm.internal.r n;
    public final /* synthetic */ C0326g0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public U0(androidx.compose.ui.input.pointer.B b, kotlin.jvm.functions.c cVar, Function1 function1, C0326g0 c0326g0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = b;
        this.m = (kotlin.coroutines.jvm.internal.i) cVar;
        this.n = (kotlin.jvm.internal.r) function1;
        this.o = c0326g0;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        ?? r3 = this.n;
        C0326g0 c0326g0 = this.o;
        U0 u0 = new U0(this.l, this.m, r3, c0326g0, hVar);
        u0.k = obj;
        return u0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((U0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r5v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    /* JADX WARN: Type inference failed for: r6v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            T0 t0 = new T0((kotlinx.coroutines.C) this.k, this.m, this.n, this.o, null);
            this.j = 1;
            if (AbstractC0349s0.d(this.l, t0, this) == aVar) {
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
