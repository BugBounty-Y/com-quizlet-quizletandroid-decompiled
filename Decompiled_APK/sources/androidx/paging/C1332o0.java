package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.paging.o0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1332o0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public C1337r0 j;
    public kotlinx.coroutines.sync.c k;
    public C1336q0 l;
    public int m;
    public final /* synthetic */ C1336q0 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1332o0(C1336q0 c1336q0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = c1336q0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1332o0(this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1332o0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x005f, code lost:
    
        if (androidx.paging.C1336q0.a(r1, r4, r3, r7) == r0) goto L18;
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
            int r1 = r7.m
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L22
            if (r1 == r3) goto L18
            if (r1 != r2) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L62
        L10:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L18:
            androidx.paging.q0 r1 = r7.l
            kotlinx.coroutines.sync.c r3 = r7.k
            androidx.paging.r0 r4 = r7.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L3b
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            androidx.paging.q0 r1 = r7.n
            androidx.paging.r0 r4 = r1.h
            kotlinx.coroutines.sync.c r8 = r4.a
            r7.j = r4
            r7.k = r8
            r7.l = r1
            r7.m = r3
            java.lang.Object r3 = r8.d(r7)
            if (r3 != r0) goto L3a
            goto L61
        L3a:
            r3 = r8
        L3b:
            r8 = 0
            androidx.paging.u0 r4 = r4.b     // Catch: java.lang.Throwable -> L65
            kotlinx.coroutines.channels.h r5 = r4.g     // Catch: java.lang.Throwable -> L65
            kotlinx.coroutines.flow.d r5 = kotlinx.coroutines.flow.e0.k(r5)     // Catch: java.lang.Throwable -> L65
            androidx.paging.t0 r6 = new androidx.paging.t0     // Catch: java.lang.Throwable -> L65
            r6.<init>(r4, r8)     // Catch: java.lang.Throwable -> L65
            androidx.paging.J0 r4 = new androidx.paging.J0     // Catch: java.lang.Throwable -> L65
            r4.<init>(r6, r5)     // Catch: java.lang.Throwable -> L65
            r3.f(r8)
            androidx.paging.G r3 = androidx.paging.G.b
            r7.j = r8
            r7.k = r8
            r7.l = r8
            r7.m = r2
            java.lang.Object r8 = androidx.paging.C1336q0.a(r1, r4, r3, r7)
            if (r8 != r0) goto L62
        L61:
            return r0
        L62:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        L65:
            r0 = move-exception
            r3.f(r8)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.C1332o0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
