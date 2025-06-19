package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: androidx.paging.n0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1330n0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.sync.c j;
    public InterfaceC5002j k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ C1336q0 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1330n0(C1336q0 c1336q0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = c1336q0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1330n0 c1330n0 = new C1330n0(this.n, hVar);
        c1330n0.m = obj;
        return c1330n0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1330n0) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x005f, code lost:
    
        if (r1.emit(r3, r5) == r0) goto L18;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.l
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L24
            if (r1 == r3) goto L18
            if (r1 != r2) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L62
        L10:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L18:
            kotlinx.coroutines.flow.j r1 = r5.k
            kotlinx.coroutines.sync.c r3 = r5.j
            java.lang.Object r4 = r5.m
            androidx.paging.r0 r4 = (androidx.paging.C1337r0) r4
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L42
        L24:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r5.m
            r1 = r6
            kotlinx.coroutines.flow.j r1 = (kotlinx.coroutines.flow.InterfaceC5002j) r1
            androidx.paging.q0 r6 = r5.n
            androidx.paging.r0 r4 = r6.h
            kotlinx.coroutines.sync.c r6 = r4.a
            r5.m = r4
            r5.j = r6
            r5.k = r1
            r5.l = r3
            java.lang.Object r3 = r6.d(r5)
            if (r3 != r0) goto L41
            goto L61
        L41:
            r3 = r6
        L42:
            r6 = 0
            androidx.paging.u0 r4 = r4.b     // Catch: java.lang.Throwable -> L65
            io.ktor.client.plugins.api.d r4 = r4.j     // Catch: java.lang.Throwable -> L65
            androidx.paging.F r4 = r4.B()     // Catch: java.lang.Throwable -> L65
            r3.f(r6)
            androidx.paging.M r3 = new androidx.paging.M
            r3.<init>(r4, r6)
            r5.m = r6
            r5.j = r6
            r5.k = r6
            r5.l = r2
            java.lang.Object r6 = r1.emit(r3, r5)
            if (r6 != r0) goto L62
        L61:
            return r0
        L62:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        L65:
            r0 = move-exception
            r3.f(r6)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.C1330n0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
