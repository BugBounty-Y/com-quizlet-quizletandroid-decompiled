package kotlin.coroutines.intrinsics;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public int j;
    public final /* synthetic */ Function2 k;
    public final /* synthetic */ kotlin.coroutines.h l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(kotlin.coroutines.h hVar, CoroutineContext coroutineContext, Function2 function2, kotlin.coroutines.h hVar2) {
        super(hVar, coroutineContext);
        this.k = function2;
        this.l = hVar2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("This coroutine had already completed");
            }
            this.j = 2;
            Z.e(obj);
            return obj;
        }
        this.j = 1;
        Z.e(obj);
        Function2 function2 = this.k;
        Intrinsics.e(function2, "null cannot be cast to non-null type kotlin.Function2<R of kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt.createCoroutineUnintercepted$lambda$1, kotlin.coroutines.Continuation<T of kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt.createCoroutineUnintercepted$lambda$1>, kotlin.Any?>");
        O.d(2, function2);
        return function2.invoke(this.l, this);
    }
}
