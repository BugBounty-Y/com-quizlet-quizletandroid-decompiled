package androidx.compose.animation;

import androidx.compose.animation.core.C0238e;
import androidx.compose.animation.core.C0252l;
import androidx.compose.animation.core.InterfaceC0256n;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class k0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ j0 k;
    public final /* synthetic */ long l;
    public final /* synthetic */ m0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k0(j0 j0Var, long j, m0 m0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = j0Var;
        this.l = j;
        this.m = m0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k0(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        j0 j0Var = this.k;
        m0 m0Var = this.m;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0238e c0238e = j0Var.a;
            androidx.compose.ui.unit.j jVar = new androidx.compose.ui.unit.j(this.l);
            InterfaceC0256n interfaceC0256n = m0Var.o;
            this.j = 1;
            obj = C0238e.c(c0238e, jVar, interfaceC0256n, null, this, 12);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        if (((C0252l) obj).b == 2) {
            m0Var.getClass();
        }
        return Unit.a;
    }
}
