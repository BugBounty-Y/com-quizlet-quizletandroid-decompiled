package androidx.glance.appwidget;

import java.util.concurrent.atomic.AtomicReference;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.glance.appwidget.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1188p implements InterfaceC1222z {
    public final /* synthetic */ AtomicReference a;
    public final /* synthetic */ kotlinx.coroutines.channels.u b;

    public C1188p(AtomicReference atomicReference, kotlinx.coroutines.channels.u uVar) {
        this.a = atomicReference;
        this.b = uVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(androidx.compose.runtime.internal.d r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r6 = this;
            boolean r0 = r8 instanceof androidx.glance.appwidget.C1186o
            if (r0 == 0) goto L13
            r0 = r8
            androidx.glance.appwidget.o r0 = (androidx.glance.appwidget.C1186o) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.glance.appwidget.o r0 = new androidx.glance.appwidget.o
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 == r3) goto L2b
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L2b:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L6e
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r7
            java.util.concurrent.atomic.AtomicReference r8 = r6.a
            kotlinx.coroutines.channels.u r2 = r6.b
            r0.m = r3
            kotlinx.coroutines.l r4 = new kotlinx.coroutines.l
            kotlin.coroutines.h r5 = kotlin.coroutines.intrinsics.h.b(r0)
            r4.<init>(r3, r5)
            r4.r()
            androidx.credentials.playservices.controllers.BeginSignIn.c r3 = new androidx.credentials.playservices.controllers.BeginSignIn.c
            r5 = 3
            r3.<init>(r2, r5)
            r4.u(r3)
            java.lang.Object r8 = r8.getAndSet(r4)
            kotlinx.coroutines.k r8 = (kotlinx.coroutines.InterfaceC5026k) r8
            if (r8 == 0) goto L5b
            r3 = 0
            r8.b(r3)
        L5b:
            kotlinx.coroutines.channels.t r2 = (kotlinx.coroutines.channels.t) r2
            r2.o(r7)
            java.lang.Object r7 = r4.q()
            if (r7 != r1) goto L6b
            java.lang.String r8 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r8)
        L6b:
            if (r7 != r1) goto L6e
            return
        L6e:
            kotlin.KotlinNothingValueException r7 = new kotlin.KotlinNothingValueException
            r7.<init>()
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.C1188p.b(androidx.compose.runtime.internal.d, kotlin.coroutines.jvm.internal.c):void");
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
