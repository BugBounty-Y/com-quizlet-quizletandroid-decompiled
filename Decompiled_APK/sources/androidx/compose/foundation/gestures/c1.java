package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class c1 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0326g0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c1(C0326g0 c0326g0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0326g0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c1(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c1) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            this.j = 1;
            if (this.k.b(this) == aVar) {
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
