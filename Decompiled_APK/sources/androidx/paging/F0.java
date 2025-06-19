package androidx.paging;

import androidx.compose.foundation.text.C0494i0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class F0 extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ androidx.paging.compose.c k;
    public final /* synthetic */ C1351y0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F0(androidx.paging.compose.c cVar, C1351y0 c1351y0, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = cVar;
        this.l = c1351y0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new F0(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((F0) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C1351y0 c1351y0 = this.l;
            com.quizlet.data.repository.qclass.c cVar = c1351y0.b;
            androidx.paging.compose.c cVar2 = this.k;
            h1 h1Var = cVar2.c;
            cVar2.c = cVar;
            if (h1Var instanceof D0) {
                ((D0) h1Var).getClass();
            }
            C0494i0 c0494i0 = new C0494i0(8, cVar2, c1351y0);
            this.j = 1;
            if (c1351y0.a.b(c0494i0, this) == aVar) {
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
