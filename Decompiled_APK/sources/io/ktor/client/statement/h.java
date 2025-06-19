package io.ktor.client.statement;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h {
    public final io.ktor.client.request.c a;
    public final io.ktor.client.c b;

    public h(io.ktor.client.request.c builder, io.ktor.client.c client) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        Intrinsics.checkNotNullParameter(client, "client");
        this.a = builder;
        this.b = client;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(io.ktor.client.statement.b r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof io.ktor.client.statement.f
            if (r0 == 0) goto L13
            r0 = r6
            io.ktor.client.statement.f r0 = (io.ktor.client.statement.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            io.ktor.client.statement.f r0 = new io.ktor.client.statement.f
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L59
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.coroutines.CoroutineContext r6 = r5.getCoroutineContext()
            kotlinx.coroutines.i0 r2 = kotlinx.coroutines.C5023i0.a
            kotlin.coroutines.CoroutineContext$Element r6 = r6.get(r2)
            kotlin.jvm.internal.Intrinsics.d(r6)
            kotlinx.coroutines.s r6 = (kotlinx.coroutines.InterfaceC5034s) r6
            r2 = r6
            kotlinx.coroutines.k0 r2 = (kotlinx.coroutines.C5027k0) r2
            r2.k0()
            io.ktor.utils.io.n r5 = r5.c()     // Catch: java.lang.Throwable -> L4e
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3225o7.d(r5)     // Catch: java.lang.Throwable -> L4e
        L4e:
            r0.l = r3
            kotlinx.coroutines.q0 r6 = (kotlinx.coroutines.q0) r6
            java.lang.Object r5 = r6.p(r0)
            if (r5 != r1) goto L59
            return r1
        L59:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.statement.h.a(io.ktor.client.statement.b, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x009c A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:38:0x009d A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r8 = this;
            boolean r0 = r9 instanceof io.ktor.client.statement.g
            if (r0 == 0) goto L13
            r0 = r9
            io.ktor.client.statement.g r0 = (io.ktor.client.statement.g) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            io.ktor.client.statement.g r0 = new io.ktor.client.statement.g
            r0.<init>(r8, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 3
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L4e
            if (r2 == r5) goto L46
            if (r2 == r4) goto L3c
            if (r2 != r3) goto L34
            java.lang.Object r0 = r0.j
            io.ktor.client.statement.b r0 = (io.ktor.client.statement.b) r0
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.util.concurrent.CancellationException -> L31
            return r0
        L31:
            r9 = move-exception
            goto L9e
        L34:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L3c:
            io.ktor.client.call.b r2 = r0.k
            java.lang.Object r4 = r0.j
            io.ktor.client.statement.h r4 = (io.ktor.client.statement.h) r4
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.util.concurrent.CancellationException -> L31
            goto L85
        L46:
            java.lang.Object r2 = r0.j
            io.ktor.client.statement.h r2 = (io.ktor.client.statement.h) r2
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.util.concurrent.CancellationException -> L31
            goto L72
        L4e:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            io.ktor.client.request.c r9 = new io.ktor.client.request.c     // Catch: java.util.concurrent.CancellationException -> L31
            r9.<init>()     // Catch: java.util.concurrent.CancellationException -> L31
            io.ktor.client.request.c r2 = r8.a     // Catch: java.util.concurrent.CancellationException -> L31
            java.lang.String r6 = "builder"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r6)     // Catch: java.util.concurrent.CancellationException -> L31
            kotlinx.coroutines.A0 r6 = r2.e     // Catch: java.util.concurrent.CancellationException -> L31
            r9.e = r6     // Catch: java.util.concurrent.CancellationException -> L31
            r9.b(r2)     // Catch: java.util.concurrent.CancellationException -> L31
            io.ktor.client.c r2 = r8.b     // Catch: java.util.concurrent.CancellationException -> L31
            r0.j = r8     // Catch: java.util.concurrent.CancellationException -> L31
            r0.n = r5     // Catch: java.util.concurrent.CancellationException -> L31
            java.lang.Object r9 = r2.a(r9, r0)     // Catch: java.util.concurrent.CancellationException -> L31
            if (r9 != r1) goto L71
            goto L9c
        L71:
            r2 = r8
        L72:
            io.ktor.client.call.b r9 = (io.ktor.client.call.b) r9     // Catch: java.util.concurrent.CancellationException -> L31
            r0.j = r2     // Catch: java.util.concurrent.CancellationException -> L31
            r0.k = r9     // Catch: java.util.concurrent.CancellationException -> L31
            r0.n = r4     // Catch: java.util.concurrent.CancellationException -> L31
            java.lang.Object r4 = com.google.android.gms.internal.mlkit_vision_barcode.T6.a(r9, r0)     // Catch: java.util.concurrent.CancellationException -> L31
            if (r4 != r1) goto L81
            goto L9c
        L81:
            r7 = r2
            r2 = r9
            r9 = r4
            r4 = r7
        L85:
            io.ktor.client.call.b r9 = (io.ktor.client.call.b) r9     // Catch: java.util.concurrent.CancellationException -> L31
            io.ktor.client.statement.b r9 = r9.d()     // Catch: java.util.concurrent.CancellationException -> L31
            io.ktor.client.statement.b r2 = r2.d()     // Catch: java.util.concurrent.CancellationException -> L31
            r0.j = r9     // Catch: java.util.concurrent.CancellationException -> L31
            r5 = 0
            r0.k = r5     // Catch: java.util.concurrent.CancellationException -> L31
            r0.n = r3     // Catch: java.util.concurrent.CancellationException -> L31
            java.lang.Object r0 = r4.a(r2, r0)     // Catch: java.util.concurrent.CancellationException -> L31
            if (r0 != r1) goto L9d
        L9c:
            return r1
        L9d:
            return r9
        L9e:
            java.lang.Throwable r9 = io.ktor.client.utils.a.a(r9)
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.statement.h.b(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final String toString() {
        return "HttpStatement[" + this.a.a + ']';
    }
}
