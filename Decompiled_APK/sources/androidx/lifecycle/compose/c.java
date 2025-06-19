package androidx.lifecycle.compose;

import androidx.compose.runtime.C0807l0;
import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.B;
import androidx.lifecycle.C;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.a0;

/* loaded from: classes.dex */
public final class c extends i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C l;
    public final /* synthetic */ B m;
    public final /* synthetic */ CoroutineContext n;
    public final /* synthetic */ a0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(C c, B b, CoroutineContext coroutineContext, a0 a0Var, h hVar) {
        super(2, hVar);
        this.l = c;
        this.m = b;
        this.n = coroutineContext;
        this.o = a0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        c cVar = new c(this.l, this.m, this.n, this.o, hVar);
        cVar.k = obj;
        return cVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C0807l0) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            b bVar = new b(this.n, this.o, (C0807l0) this.k, null);
            this.j = 1;
            if (p0.l(this.l, this.m, bVar, this) == aVar) {
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
