package androidx.glance.session;

import androidx.camera.camera2.internal.s0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class J extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ K k;
    public final /* synthetic */ s0 l;
    public final /* synthetic */ kotlinx.coroutines.C m;
    public final /* synthetic */ x n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public J(K k, s0 s0Var, kotlinx.coroutines.C c, x xVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = k;
        this.l = s0Var;
        this.m = c;
        this.n = xVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new J(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((J) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objN;
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0 && i != 1) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        Z.e(obj);
        do {
            K k = this.k;
            Object obj3 = k.b.get();
            Intrinsics.d(obj3);
            long jLongValue = ((Number) obj3).longValue();
            this.l.getClass();
            if (jLongValue <= System.currentTimeMillis()) {
                kotlinx.coroutines.E.i(this.m, new TimeoutCancellationException("Timed out of executing block.", this.n.hashCode()));
                return Unit.a;
            }
            long jA = k.a();
            this.j = 1;
            objN = kotlinx.coroutines.E.n(kotlinx.coroutines.E.H(jA), this);
            if (objN != kotlin.coroutines.intrinsics.a.a) {
                objN = Unit.a;
            }
        } while (objN != obj2);
        return obj2;
    }
}
