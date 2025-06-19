package io.ktor.client.plugins;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class U implements e0 {
    public final int a;
    public final io.ktor.client.c b;
    public int c;
    public io.ktor.client.call.b d;

    public U(int i, io.ktor.client.c client) {
        Intrinsics.checkNotNullParameter(client, "client");
        this.a = i;
        this.b = client;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // io.ktor.client.plugins.e0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(io.ktor.client.request.c r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof io.ktor.client.plugins.T
            if (r0 == 0) goto L13
            r0 = r7
            io.ktor.client.plugins.T r0 = (io.ktor.client.plugins.T) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            io.ktor.client.plugins.T r0 = new io.ktor.client.plugins.T
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L32
            if (r2 != r4) goto L2a
            io.ktor.client.plugins.U r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L57
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            io.ktor.client.call.b r7 = r5.d
            if (r7 == 0) goto L3c
            kotlinx.coroutines.E.i(r7, r3)
        L3c:
            int r7 = r5.c
            int r2 = r5.a
            if (r7 >= r2) goto L7b
            int r7 = r7 + r4
            r5.c = r7
            io.ktor.client.c r7 = r5.b
            io.ktor.client.request.h r7 = r7.g
            java.lang.Object r2 = r6.d
            r0.j = r5
            r0.m = r4
            java.lang.Object r7 = r7.a(r6, r2, r0)
            if (r7 != r1) goto L56
            return r1
        L56:
            r6 = r5
        L57:
            boolean r0 = r7 instanceof io.ktor.client.call.b
            if (r0 == 0) goto L5e
            r3 = r7
            io.ktor.client.call.b r3 = (io.ktor.client.call.b) r3
        L5e:
            if (r3 == 0) goto L63
            r6.d = r3
            return r3
        L63:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r1 = "Failed to execute send pipeline. Expected [HttpClientCall], but received "
            r0.<init>(r1)
            r0.append(r7)
            java.lang.String r7 = r0.toString()
            java.lang.String r7 = r7.toString()
            r6.<init>(r7)
            throw r6
        L7b:
            io.ktor.client.plugins.SendCountExceedException r6 = new io.ktor.client.plugins.SendCountExceedException
            java.lang.StringBuilder r7 = new java.lang.StringBuilder
            java.lang.String r0 = "Max send count "
            r7.<init>(r0)
            r7.append(r2)
            java.lang.String r0 = " exceeded. Consider increasing the property maxSendCount if more is required."
            r7.append(r0)
            java.lang.String r7 = r7.toString()
            java.lang.String r0 = "message"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r0)
            r6.<init>(r7)
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.U.a(io.ktor.client.request.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
