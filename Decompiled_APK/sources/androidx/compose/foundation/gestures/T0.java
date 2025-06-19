package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class T0 extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ kotlinx.coroutines.C m;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i n;
    public final /* synthetic */ kotlin.jvm.internal.r o;
    public final /* synthetic */ C0326g0 p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public T0(kotlinx.coroutines.C c, kotlin.jvm.functions.c cVar, Function1 function1, C0326g0 c0326g0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = c;
        this.n = (kotlin.coroutines.jvm.internal.i) cVar;
        this.o = (kotlin.jvm.internal.r) function1;
        this.p = c0326g0;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        ?? r3 = this.o;
        C0326g0 c0326g0 = this.p;
        T0 t0 = new T0(this.m, this.n, r3, c0326g0, hVar);
        t0.l = obj;
        return t0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((T0) create((androidx.compose.ui.input.pointer.z) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x005e, code lost:
    
        if (r10 == r0) goto L18;
     */
    /* JADX WARN: Type inference failed for: r0v2, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r8v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.k
            androidx.compose.foundation.gestures.g0 r2 = r9.p
            kotlinx.coroutines.C r3 = r9.m
            r4 = 3
            r5 = 0
            r6 = 2
            r7 = 1
            if (r1 == 0) goto L26
            if (r1 == r7) goto L1e
            if (r1 != r6) goto L16
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L61
        L16:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L1e:
            java.lang.Object r1 = r9.l
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L41
        L26:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.lang.Object r10 = r9.l
            r1 = r10
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            androidx.compose.foundation.gestures.P0 r10 = new androidx.compose.foundation.gestures.P0
            r10.<init>(r2, r5)
            kotlinx.coroutines.E.A(r3, r5, r5, r10, r4)
            r9.l = r1
            r9.k = r7
            java.lang.Object r10 = androidx.compose.foundation.gestures.k1.c(r1, r9, r4)
            if (r10 != r0) goto L41
            goto L60
        L41:
            androidx.compose.ui.input.pointer.n r10 = (androidx.compose.ui.input.pointer.n) r10
            r10.a()
            androidx.compose.foundation.gestures.S r7 = androidx.compose.foundation.gestures.k1.a
            kotlin.coroutines.jvm.internal.i r8 = r9.n
            if (r8 == r7) goto L54
            androidx.compose.foundation.gestures.Q0 r7 = new androidx.compose.foundation.gestures.Q0
            r7.<init>(r8, r2, r10, r5)
            kotlinx.coroutines.E.A(r3, r5, r5, r7, r4)
        L54:
            r9.l = r5
            r9.k = r6
            androidx.compose.ui.input.pointer.g r10 = androidx.compose.ui.input.pointer.g.b
            java.lang.Object r10 = androidx.compose.foundation.gestures.k1.e(r1, r10, r9)
            if (r10 != r0) goto L61
        L60:
            return r0
        L61:
            androidx.compose.ui.input.pointer.n r10 = (androidx.compose.ui.input.pointer.n) r10
            if (r10 != 0) goto L6e
            androidx.compose.foundation.gestures.R0 r10 = new androidx.compose.foundation.gestures.R0
            r10.<init>(r2, r5)
            kotlinx.coroutines.E.A(r3, r5, r5, r10, r4)
            goto L85
        L6e:
            r10.a()
            androidx.compose.foundation.gestures.S0 r0 = new androidx.compose.foundation.gestures.S0
            r0.<init>(r2, r5)
            kotlinx.coroutines.E.A(r3, r5, r5, r0, r4)
            kotlin.jvm.internal.r r0 = r9.o
            androidx.compose.ui.geometry.b r1 = new androidx.compose.ui.geometry.b
            long r2 = r10.c
            r1.<init>(r2)
            r0.invoke(r1)
        L85:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.T0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
