package com.google.android.gms.internal.mlkit_vision_barcode;

/* loaded from: classes2.dex */
public abstract class T6 {
    public static final /* synthetic */ int a = 0;

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(io.ktor.client.call.b r4, kotlin.coroutines.jvm.internal.c r5) throws java.io.EOFException {
        /*
            boolean r0 = r5 instanceof io.ktor.client.call.c
            if (r0 == 0) goto L13
            r0 = r5
            io.ktor.client.call.c r0 = (io.ktor.client.call.c) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            io.ktor.client.call.c r0 = new io.ktor.client.call.c
            r0.<init>(r5)
        L18:
            java.lang.Object r5 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            io.ktor.client.call.b r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L47
        L29:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            io.ktor.client.statement.b r5 = r4.d()
            io.ktor.utils.io.n r5 = r5.c()
            r0.j = r4
            r0.l = r3
            java.lang.Object r5 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7.l(r5, r0)
            if (r5 != r1) goto L47
            return r1
        L47:
            kotlinx.io.i r5 = (kotlinx.io.i) r5
            java.lang.String r0 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r0)
            r0 = -1
            byte[] r5 = kotlinx.io.j.e(r5, r0)
            io.ktor.client.call.d r0 = new io.ktor.client.call.d
            io.ktor.client.c r1 = r4.a
            io.ktor.client.request.b r2 = r4.c()
            io.ktor.client.statement.b r4 = r4.d()
            r0.<init>(r1, r2, r4, r5)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.T6.a(io.ktor.client.call.b, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public abstract void b(int i, byte[] bArr, int i2);
}
