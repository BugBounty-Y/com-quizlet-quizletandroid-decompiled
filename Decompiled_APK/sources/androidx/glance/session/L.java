package androidx.glance.session;

import androidx.camera.camera2.internal.s0;
import androidx.glance.appwidget.protobuf.Z;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class L extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ x l;
    public final /* synthetic */ s0 m;
    public final /* synthetic */ kotlinx.coroutines.C n;
    public final /* synthetic */ AtomicReference o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(x xVar, s0 s0Var, kotlinx.coroutines.C c, AtomicReference atomicReference, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = xVar;
        this.m = s0Var;
        this.n = c;
        this.o = atomicReference;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        L l = new L(this.l, this.m, this.n, this.o, hVar);
        l.k = obj;
        return l;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((L) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        K k = new K((kotlinx.coroutines.C) this.k, this.m, this.n, this.l, this.o);
        this.j = 1;
        Object objInvoke = this.l.invoke(k, this);
        return objInvoke == aVar ? aVar : objInvoke;
    }
}
