package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: androidx.paging.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1342u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlin.jvm.internal.J j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ J0 m;
    public final /* synthetic */ C1319i n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1342u(J0 j0, C1319i c1319i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = j0;
        this.n = c1319i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1342u c1342u = new C1342u(this.m, this.n, hVar);
        c1342u.l = obj;
        return c1342u;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1342u) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x0053, code lost:
    
        if (r7.m.b(r8, r7) == r0) goto L16;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.k
            r2 = 0
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L23
            if (r1 == r4) goto L19
            if (r1 != r3) goto L11
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L56
        L11:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L19:
            kotlin.jvm.internal.J r1 = r7.j
            java.lang.Object r4 = r7.l
            kotlinx.coroutines.flow.j r4 = (kotlinx.coroutines.flow.InterfaceC5002j) r4
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L3f
        L23:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.lang.Object r8 = r7.l
            kotlinx.coroutines.flow.j r8 = (kotlinx.coroutines.flow.InterfaceC5002j) r8
            kotlin.jvm.internal.J r1 = new kotlin.jvm.internal.J
            r1.<init>()
            r1.a = r2
            r7.l = r8
            r7.j = r1
            r7.k = r4
            java.lang.Object r4 = r8.emit(r2, r7)
            if (r4 != r0) goto L3e
            goto L55
        L3e:
            r4 = r8
        L3f:
            androidx.compose.animation.y r8 = new androidx.compose.animation.y
            androidx.paging.i r5 = r7.n
            r6 = 5
            r8.<init>(r1, r5, r4, r6)
            r7.l = r2
            r7.j = r2
            r7.k = r3
            androidx.paging.J0 r1 = r7.m
            java.lang.Object r8 = r1.b(r8, r7)
            if (r8 != r0) goto L56
        L55:
            return r0
        L56:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.C1342u.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
