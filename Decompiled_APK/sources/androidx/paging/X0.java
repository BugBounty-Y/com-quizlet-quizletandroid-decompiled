package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class X0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ kotlinx.coroutines.channels.h k;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public X0(kotlinx.coroutines.channels.h hVar, Function2 function2, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
        this.l = (kotlin.coroutines.jvm.internal.i) function2;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new X0(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((X0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        kotlinx.coroutines.channels.h hVar = this.k;
        try {
            if (i == 0) {
                androidx.glance.appwidget.protobuf.Z.e(obj);
                W0 w0 = new W0(hVar, this.l, null);
                this.j = 1;
                if (kotlinx.coroutines.E.m(w0, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
            }
            hVar.i(null);
        } catch (Throwable th) {
            hVar.k(th, false);
        }
        return Unit.a;
    }
}
