package androidx.glance.session;

import android.content.Context;
import androidx.compose.runtime.C0832v0;
import androidx.compose.runtime.EnumC0817q0;
import androidx.glance.appwidget.B0;
import androidx.glance.appwidget.C1182m;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes.dex */
public final class B extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C1182m l;
    public final /* synthetic */ C0832v0 m;
    public final /* synthetic */ kotlin.jvm.internal.I n;
    public final /* synthetic */ s0 o;
    public final /* synthetic */ Context p;
    public final /* synthetic */ B0 q;
    public final /* synthetic */ K r;
    public final /* synthetic */ I s;
    public final /* synthetic */ kotlinx.coroutines.C t;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(C1182m c1182m, C0832v0 c0832v0, kotlin.jvm.internal.I i, s0 s0Var, Context context, B0 b0, K k, I i2, kotlinx.coroutines.C c, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c1182m;
        this.m = c0832v0;
        this.n = i;
        this.o = s0Var;
        this.p = context;
        this.q = b0;
        this.r = k;
        this.s = i2;
        this.t = c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        B b = new B(this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s, this.t, hVar);
        b.k = obj;
        return b;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((B) create((EnumC0817q0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x007a, code lost:
    
        if (kotlin.Unit.a == r0) goto L27;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) throws java.lang.Throwable {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.j
            kotlin.jvm.internal.I r2 = r12.n
            androidx.compose.runtime.v0 r3 = r12.m
            kotlinx.coroutines.flow.s0 r4 = r12.o
            r5 = 0
            r6 = 2
            r7 = 1
            if (r1 == 0) goto L23
            if (r1 == r7) goto L1f
            if (r1 != r6) goto L17
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L7d
        L17:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L1f:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L5d
        L23:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            java.lang.Object r13 = r12.k
            androidx.compose.runtime.q0 r13 = (androidx.compose.runtime.EnumC0817q0) r13
            int r13 = r13.ordinal()
            if (r13 == 0) goto L8b
            r1 = 4
            if (r13 == r1) goto L34
            goto L90
        L34:
            long r8 = r3.a
            long r10 = r2.a
            int r13 = (r8 > r10 ? 1 : (r8 == r10 ? 0 : -1))
            if (r13 > 0) goto L48
            java.lang.Object r13 = r4.getValue()
            java.lang.Boolean r13 = (java.lang.Boolean) r13
            boolean r13 = r13.booleanValue()
            if (r13 != 0) goto L86
        L48:
            androidx.glance.appwidget.B0 r13 = r12.q
            androidx.glance.k r13 = r13.copy()
            androidx.glance.m r13 = (androidx.glance.m) r13
            r12.j = r7
            androidx.glance.appwidget.m r1 = r12.l
            android.content.Context r7 = r12.p
            java.lang.Object r13 = r1.b(r7, r13, r12)
            if (r13 != r0) goto L5d
            goto L7c
        L5d:
            java.lang.Boolean r13 = (java.lang.Boolean) r13
            boolean r13 = r13.booleanValue()
            java.lang.Object r1 = r4.getValue()
            java.lang.Boolean r1 = (java.lang.Boolean) r1
            boolean r1 = r1.booleanValue()
            if (r1 != 0) goto L86
            if (r13 == 0) goto L86
            java.lang.Boolean r13 = java.lang.Boolean.TRUE
            r12.j = r6
            r4.m(r5, r13)
            kotlin.Unit r13 = kotlin.Unit.a
            if (r13 != r0) goto L7d
        L7c:
            return r0
        L7d:
            androidx.glance.session.I r13 = r12.s
            long r0 = r13.a
            androidx.glance.session.K r13 = r12.r
            r13.b(r0)
        L86:
            long r0 = r3.a
            r2.a = r0
            goto L90
        L8b:
            kotlinx.coroutines.C r13 = r12.t
            kotlinx.coroutines.E.i(r13, r5)
        L90:
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.session.B.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
