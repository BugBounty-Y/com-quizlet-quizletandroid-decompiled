package com.perimeterx.mobile_sdk.session;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public kotlinx.coroutines.sync.c k;
    public d l;
    public int m;
    public final /* synthetic */ d n;
    public final /* synthetic */ boolean o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(d dVar, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = dVar;
        this.o = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new q(this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new q(this.n, this.o, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0082  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            r9 = this;
            java.lang.String r0 = "iterator(...)"
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r9.m
            java.lang.String r3 = "next(...)"
            r4 = 2
            r5 = 1
            r6 = 0
            if (r2 == 0) goto L2d
            if (r2 == r5) goto L21
            if (r2 != r4) goto L19
            java.lang.Object r0 = r9.j
            java.util.Iterator r0 = (java.util.Iterator) r0
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L7c
        L19:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L21:
            com.perimeterx.mobile_sdk.session.d r2 = r9.l
            kotlinx.coroutines.sync.c r5 = r9.k
            java.lang.Object r7 = r9.j
            java.util.ArrayList r7 = (java.util.ArrayList) r7
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L49
        L2d:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.util.ArrayList r7 = new java.util.ArrayList
            r7.<init>()
            com.perimeterx.mobile_sdk.session.d r2 = r9.n
            kotlinx.coroutines.sync.c r10 = r2.d
            r9.j = r7
            r9.k = r10
            r9.l = r2
            r9.m = r5
            java.lang.Object r5 = r10.d(r9)
            if (r5 != r1) goto L48
            goto L9f
        L48:
            r5 = r10
        L49:
            com.perimeterx.mobile_sdk.session.m r10 = r2.b     // Catch: java.lang.Throwable -> L6a
            r8 = 0
            r10.i = r8     // Catch: java.lang.Throwable -> L6a
            java.util.ArrayList r10 = r2.c
            java.util.Iterator r2 = r10.iterator()     // Catch: java.lang.Throwable -> L6a
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r0)     // Catch: java.lang.Throwable -> L6a
        L57:
            boolean r8 = r2.hasNext()     // Catch: java.lang.Throwable -> L6a
            if (r8 == 0) goto L6c
            java.lang.Object r8 = r2.next()     // Catch: java.lang.Throwable -> L6a
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r3)     // Catch: java.lang.Throwable -> L6a
            kotlinx.coroutines.channels.l r8 = (kotlinx.coroutines.channels.l) r8     // Catch: java.lang.Throwable -> L6a
            r7.add(r8)     // Catch: java.lang.Throwable -> L6a
            goto L57
        L6a:
            r10 = move-exception
            goto La3
        L6c:
            r10.clear()     // Catch: java.lang.Throwable -> L6a
            kotlin.Unit r10 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L6a
            r5.f(r6)
            java.util.Iterator r10 = r7.iterator()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r10, r0)
            r0 = r10
        L7c:
            boolean r10 = r0.hasNext()
            if (r10 == 0) goto La0
            java.lang.Object r10 = r0.next()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r10, r3)
            kotlinx.coroutines.channels.l r10 = (kotlinx.coroutines.channels.l) r10
            boolean r2 = r9.o
            java.lang.Boolean r2 = java.lang.Boolean.valueOf(r2)
            r9.j = r0
            r9.k = r6
            r9.l = r6
            r9.m = r4
            java.lang.Object r10 = r10.s(r2, r9)
            if (r10 != r1) goto L7c
        L9f:
            return r1
        La0:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        La3:
            r5.f(r6)
            throw r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.session.q.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
