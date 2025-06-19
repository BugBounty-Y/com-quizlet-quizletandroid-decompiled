package androidx.compose.runtime;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.runtime.h0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0799h0 implements W {
    public final W a;
    public final androidx.browser.customtabs.k b = new androidx.browser.customtabs.k(1, false);

    public C0799h0(W w) {
        this.a = w;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // androidx.compose.runtime.W
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object P(kotlin.jvm.functions.Function1 r7, kotlin.coroutines.h r8) {
        /*
            r6 = this;
            boolean r0 = r8 instanceof androidx.compose.runtime.C0797g0
            if (r0 == 0) goto L13
            r0 = r8
            androidx.compose.runtime.g0 r0 = (androidx.compose.runtime.C0797g0) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.compose.runtime.g0 r0 = new androidx.compose.runtime.g0
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3a
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r8)
            return r8
        L2a:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L32:
            kotlin.jvm.functions.Function1 r7 = r0.k
            androidx.compose.runtime.h0 r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L85
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            androidx.browser.customtabs.k r8 = r6.b
            r0.j = r6
            r0.k = r7
            r0.n = r4
            java.lang.Object r2 = r8.b
            monitor-enter(r2)
            boolean r5 = r8.a     // Catch: java.lang.Throwable -> L99
            monitor-exit(r2)
            if (r5 == 0) goto L50
            kotlin.Unit r8 = kotlin.Unit.a
            goto L81
        L50:
            kotlinx.coroutines.l r2 = new kotlinx.coroutines.l
            kotlin.coroutines.h r5 = kotlin.coroutines.intrinsics.h.b(r0)
            r2.<init>(r4, r5)
            r2.r()
            java.lang.Object r4 = r8.b
            monitor-enter(r4)
            java.lang.Object r5 = r8.c     // Catch: java.lang.Throwable -> L96
            java.util.ArrayList r5 = (java.util.ArrayList) r5     // Catch: java.lang.Throwable -> L96
            r5.add(r2)     // Catch: java.lang.Throwable -> L96
            monitor-exit(r4)
            androidx.compose.foundation.text.selection.n0 r4 = new androidx.compose.foundation.text.selection.n0
            r5 = 12
            r4.<init>(r5, r8, r2)
            r2.u(r4)
            java.lang.Object r8 = r2.q()
            if (r8 != r1) goto L7c
            java.lang.String r2 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
        L7c:
            if (r8 != r1) goto L7f
            goto L81
        L7f:
            kotlin.Unit r8 = kotlin.Unit.a
        L81:
            if (r8 != r1) goto L84
            goto L94
        L84:
            r2 = r6
        L85:
            androidx.compose.runtime.W r8 = r2.a
            r2 = 0
            r0.j = r2
            r0.k = r2
            r0.n = r3
            java.lang.Object r7 = r8.P(r7, r0)
            if (r7 != r1) goto L95
        L94:
            return r1
        L95:
            return r7
        L96:
            r7 = move-exception
            monitor-exit(r4)
            throw r7
        L99:
            r7 = move-exception
            monitor-exit(r2)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0799h0.P(kotlin.jvm.functions.Function1, kotlin.coroutines.h):java.lang.Object");
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final Object fold(Object obj, Function2 operation) {
        Intrinsics.checkNotNullParameter(operation, "operation");
        return operation.invoke(obj, this);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext.Element get(kotlin.coroutines.l lVar) {
        return kotlin.coroutines.k.a(this, lVar);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext minusKey(kotlin.coroutines.l lVar) {
        return kotlin.coroutines.k.b(this, lVar);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext plus(CoroutineContext coroutineContext) {
        return kotlin.coroutines.k.c(coroutineContext, this);
    }
}
