package io.ktor.utils.io.jvm.javaio;

import io.ktor.utils.io.n;
import io.ktor.utils.io.x;
import java.io.IOException;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.B;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.E;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.io.i;

/* loaded from: classes3.dex */
public final class d implements n {
    public final kotlinx.io.b b;
    public final CoroutineContext c;
    public x d;
    public final kotlinx.io.a e;
    public final C5027k0 f;
    public final CoroutineContext g;

    public d(kotlinx.io.b source, CoroutineContext parent) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(parent, "parent");
        this.b = source;
        this.c = parent;
        this.e = new kotlinx.io.a();
        C5027k0 c5027k0 = new C5027k0((InterfaceC5025j0) parent.get(C5023i0.a));
        this.f = c5027k0;
        this.g = parent.plus(c5027k0).plus(new B("RawSourceChannel"));
    }

    @Override // io.ktor.utils.io.n
    public final void b(Throwable th) {
        if (this.d != null) {
            return;
        }
        C5027k0 c5027k0 = this.f;
        String message = th.getMessage();
        if (message == null) {
            message = "Channel was cancelled";
        }
        E.j(c5027k0, message, th);
        this.b.close();
        String message2 = th.getMessage();
        this.d = new x(new IOException(message2 != null ? message2 : "Channel was cancelled", th));
    }

    @Override // io.ktor.utils.io.n
    public final Throwable c() {
        x xVar = this.d;
        if (xVar != null) {
            return xVar.a();
        }
        return null;
    }

    @Override // io.ktor.utils.io.n
    public final i d() {
        return this.e;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // io.ktor.utils.io.n
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object e(int r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof io.ktor.utils.io.jvm.javaio.b
            if (r0 == 0) goto L13
            r0 = r6
            io.ktor.utils.io.jvm.javaio.b r0 = (io.ktor.utils.io.jvm.javaio.b) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            io.ktor.utils.io.jvm.javaio.b r0 = new io.ktor.utils.io.jvm.javaio.b
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            int r5 = r0.k
            io.ktor.utils.io.jvm.javaio.d r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L53
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            io.ktor.utils.io.x r6 = r4.d
            if (r6 == 0) goto L3d
            java.lang.Boolean r5 = java.lang.Boolean.TRUE
            return r5
        L3d:
            io.ktor.utils.io.jvm.javaio.c r6 = new io.ktor.utils.io.jvm.javaio.c
            r2 = 0
            r6.<init>(r4, r5, r2)
            r0.j = r4
            r0.k = r5
            r0.n = r3
            kotlin.coroutines.CoroutineContext r2 = r4.g
            java.lang.Object r6 = kotlinx.coroutines.E.J(r2, r6, r0)
            if (r6 != r1) goto L52
            return r1
        L52:
            r0 = r4
        L53:
            kotlinx.io.a r6 = r0.e
            long r0 = com.google.android.gms.internal.mlkit_vision_barcode.u7.c(r6)
            long r5 = (long) r5
            int r5 = (r0 > r5 ? 1 : (r0 == r5 ? 0 : -1))
            if (r5 < 0) goto L5f
            goto L60
        L5f:
            r3 = 0
        L60:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r3)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.utils.io.jvm.javaio.d.e(int, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // io.ktor.utils.io.n
    public final boolean f() {
        return this.d != null && this.e.u();
    }
}
