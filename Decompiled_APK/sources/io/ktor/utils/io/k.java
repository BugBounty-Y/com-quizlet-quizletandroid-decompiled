package io.ktor.utils.io;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.Unit;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class k implements n, t {
    public static final /* synthetic */ AtomicReferenceFieldUpdater f = AtomicReferenceFieldUpdater.newUpdater(k.class, Object.class, "suspensionSlot");
    public static final /* synthetic */ AtomicReferenceFieldUpdater g = AtomicReferenceFieldUpdater.newUpdater(k.class, Object.class, "_closedCause");
    private volatile int flushBufferSize;
    public final kotlinx.io.a b = new kotlinx.io.a();
    public final Object c = new Object();

    @NotNull
    volatile /* synthetic */ Object suspensionSlot = c.b;
    public final kotlinx.io.a d = new kotlinx.io.a();
    public final kotlinx.io.a e = new kotlinx.io.a();

    @NotNull
    volatile /* synthetic */ Object _closedCause = null;

    public final void a(Throwable th) {
        C4880a c4880a;
        if (th != null) {
            c4880a = new C4880a(th);
        } else {
            g.a.getClass();
            c4880a = C4881b.b;
        }
        g gVar = (g) f.getAndSet(this, c4880a);
        if (gVar instanceof e) {
            ((e) gVar).a(th);
        }
    }

    @Override // io.ktor.utils.io.n
    public final void b(Throwable th) {
        if (this._closedCause != null) {
            return;
        }
        x xVar = new x(th);
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = g;
        while (!atomicReferenceFieldUpdater.compareAndSet(this, null, xVar) && atomicReferenceFieldUpdater.get(this) == null) {
        }
        a(xVar.a());
    }

    @Override // io.ktor.utils.io.n
    public final Throwable c() {
        x xVar = (x) this._closedCause;
        if (xVar != null) {
            return xVar.a();
        }
        return null;
    }

    @Override // io.ktor.utils.io.n
    public final kotlinx.io.i d() throws Throwable {
        Throwable thC = c();
        if (thC != null) {
            throw thC;
        }
        kotlinx.io.a aVar = this.d;
        if (aVar.u()) {
            k();
        }
        return aVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00ad  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00d8  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00e0  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // io.ktor.utils.io.n
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object e(int r13, kotlin.coroutines.jvm.internal.c r14) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 296
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.utils.io.k.e(int, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // io.ktor.utils.io.n
    public final boolean f() {
        if (c() == null) {
            return j() && this.flushBufferSize == 0 && this.d.u();
        }
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:51:0x00c6  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00d3  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00f8  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0100  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object g(kotlin.coroutines.jvm.internal.c r12) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 307
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.utils.io.k.g(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x005d A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object h(kotlin.coroutines.h r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof io.ktor.utils.io.j
            if (r0 == 0) goto L13
            r0 = r5
            io.ktor.utils.io.j r0 = (io.ktor.utils.io.j) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            io.ktor.utils.io.j r0 = new io.ktor.utils.io.j
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            io.ktor.utils.io.k r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)     // Catch: java.lang.Throwable -> L29
            goto L44
        L29:
            r5 = move-exception
            goto L4d
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlin.p r5 = kotlin.r.b     // Catch: java.lang.Throwable -> L4b
            r0.j = r4     // Catch: java.lang.Throwable -> L4b
            r0.m = r3     // Catch: java.lang.Throwable -> L4b
            java.lang.Object r5 = r4.g(r0)     // Catch: java.lang.Throwable -> L4b
            if (r5 != r1) goto L43
            return r1
        L43:
            r0 = r4
        L44:
            kotlin.Unit r5 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L29
            kotlin.p r5 = kotlin.r.b     // Catch: java.lang.Throwable -> L29
            goto L52
        L49:
            r0 = r4
            goto L4d
        L4b:
            r5 = move-exception
            goto L49
        L4d:
            kotlin.p r1 = kotlin.r.b
            androidx.glance.appwidget.protobuf.Z.b(r5)
        L52:
            io.ktor.utils.io.x r5 = io.ktor.utils.io.y.a
        L54:
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r1 = io.ktor.utils.io.k.g
            r2 = 0
            boolean r3 = r1.compareAndSet(r0, r2, r5)
            if (r3 == 0) goto L63
            r0.a(r2)
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L63:
            java.lang.Object r1 = r1.get(r0)
            if (r1 == 0) goto L54
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.utils.io.k.h(kotlin.coroutines.h):java.lang.Object");
    }

    public final kotlinx.io.a i() throws Throwable {
        Throwable thC = c();
        if (thC != null) {
            throw thC;
        }
        if (j()) {
            throw new IOException("Channel is closed for write");
        }
        return this.e;
    }

    public final boolean j() {
        return this._closedCause != null;
    }

    public final void k() {
        synchronized (this.c) {
            this.b.G(this.d);
            this.flushBufferSize = 0;
            Unit unit = Unit.a;
        }
        g gVar = (g) this.suspensionSlot;
        if (gVar instanceof f) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = f;
            c cVar = c.b;
            while (!atomicReferenceFieldUpdater.compareAndSet(this, gVar, cVar)) {
                if (atomicReferenceFieldUpdater.get(this) != gVar) {
                    return;
                }
            }
            ((e) gVar).b();
        }
    }

    public final String toString() {
        return "ByteChannel[" + hashCode() + ']';
    }
}
