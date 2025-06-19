package androidx.activity.compose;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.F;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.C5013v;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes.dex */
public final class q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public F j;
    public int k;
    public final /* synthetic */ r l;
    public final /* synthetic */ Function2 m;
    public final /* synthetic */ com.bumptech.glide.manager.p n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(r rVar, Function2 function2, com.bumptech.glide.manager.p pVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = rVar;
        this.m = function2;
        this.n = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new q(this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((q) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        F f;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            Z.e(obj);
            if (this.l.a) {
                F f2 = new F();
                C5013v c5013v = new C5013v(e0.k((kotlinx.coroutines.channels.h) this.n.b), new p(f2, (kotlin.coroutines.h) null, 0));
                this.j = f2;
                this.k = 1;
                if (this.m.invoke(c5013v, this) == aVar) {
                    return aVar;
                }
                f = f2;
            }
            return Unit.a;
        }
        if (i != 1) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        f = this.j;
        Z.e(obj);
        if (!f.a) {
            throw new IllegalStateException("You must collect the progress flow");
        }
        return Unit.a;
    }
}
