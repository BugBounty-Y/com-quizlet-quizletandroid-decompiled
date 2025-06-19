package androidx.glance.session;

import android.content.Context;
import androidx.compose.runtime.C0832v0;
import androidx.glance.appwidget.B0;
import androidx.glance.appwidget.C1182m;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0832v0 l;
    public final /* synthetic */ C1182m m;
    public final /* synthetic */ s0 n;
    public final /* synthetic */ Context o;
    public final /* synthetic */ B0 p;
    public final /* synthetic */ K q;
    public final /* synthetic */ I r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(C0832v0 c0832v0, C1182m c1182m, s0 s0Var, Context context, B0 b0, K k, I i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0832v0;
        this.m = c1182m;
        this.n = s0Var;
        this.o = context;
        this.p = b0;
        this.q = k;
        this.r = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C c = new C(this.l, this.m, this.n, this.o, this.p, this.q, this.r, hVar);
        c.k = obj;
        return c;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
            kotlin.jvm.internal.I i2 = new kotlin.jvm.internal.I();
            C0832v0 c0832v0 = this.l;
            i2.a = c0832v0.a;
            B b = new B(this.m, c0832v0, i2, this.n, this.o, this.p, this.q, this.r, c, null);
            this.j = 1;
            if (e0.i(c0832v0.u, b, this) == aVar) {
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
