package coil3.network.okhttp.internal;

import okhttp3.A;

/* loaded from: classes.dex */
public final class b {
    public final A a;

    public /* synthetic */ b(A a) {
        this.a = a;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00ab  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r10v7, types: [kotlin.jvm.functions.Function2] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Object a(okhttp3.A r8, coil3.network.s r9, coil3.network.k r10, kotlin.coroutines.jvm.internal.c r11) {
        /*
            boolean r0 = r11 instanceof coil3.network.okhttp.internal.a
            if (r0 == 0) goto L13
            r0 = r11
            coil3.network.okhttp.internal.a r0 = (coil3.network.okhttp.internal.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            coil3.network.okhttp.internal.a r0 = new coil3.network.okhttp.internal.a
            r0.<init>(r11)
        L18:
            java.lang.Object r11 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 3
            r4 = 2
            r5 = 1
            r6 = 0
            if (r2 == 0) goto L51
            if (r2 == r5) goto L46
            if (r2 == r4) goto L3e
            if (r2 != r3) goto L36
            java.lang.Object r8 = r0.j
            java.io.Closeable r8 = (java.io.Closeable) r8
            androidx.glance.appwidget.protobuf.Z.e(r11)     // Catch: java.lang.Throwable -> L33
            goto Lac
        L33:
            r9 = move-exception
            goto Lb4
        L36:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L3e:
            java.lang.Object r8 = r0.j
            kotlin.jvm.functions.Function2 r8 = (kotlin.jvm.functions.Function2) r8
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L96
        L46:
            okhttp3.d r8 = r0.k
            java.lang.Object r9 = r0.j
            r10 = r9
            kotlin.jvm.functions.Function2 r10 = (kotlin.jvm.functions.Function2) r10
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L61
        L51:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            r0.j = r10
            r0.k = r8
            r0.m = r5
            okhttp3.C r11 = com.google.android.gms.internal.mlkit_vision_common.AbstractC3461h.c(r9, r0)
            if (r11 != r1) goto L61
            goto Laa
        L61:
            okhttp3.C r11 = (okhttp3.C) r11
            okhttp3.A r8 = (okhttp3.A) r8
            okhttp3.internal.connection.g r8 = r8.c(r11)
            r0.j = r10
            r0.k = r6
            r0.m = r4
            kotlinx.coroutines.l r9 = new kotlinx.coroutines.l
            kotlin.coroutines.h r11 = kotlin.coroutines.intrinsics.h.b(r0)
            r9.<init>(r5, r11)
            r9.r()
            coil3.network.okhttp.internal.c r11 = new coil3.network.okhttp.internal.c
            r2 = 0
            r11.<init>(r2, r8, r9)
            com.google.firebase.perf.network.FirebasePerfOkHttpClient.enqueue(r8, r11)
            r9.u(r11)
            java.lang.Object r11 = r9.q()
            if (r11 != r1) goto L92
            java.lang.String r8 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r8)
        L92:
            if (r11 != r1) goto L95
            goto Laa
        L95:
            r8 = r10
        L96:
            r9 = r11
            java.io.Closeable r9 = (java.io.Closeable) r9
            r10 = r9
            okhttp3.H r10 = (okhttp3.H) r10     // Catch: java.lang.Throwable -> Lb0
            coil3.network.t r10 = com.google.android.gms.internal.mlkit_vision_common.AbstractC3461h.b(r10)     // Catch: java.lang.Throwable -> Lb0
            r0.j = r9     // Catch: java.lang.Throwable -> Lb0
            r0.m = r3     // Catch: java.lang.Throwable -> Lb0
            java.lang.Object r11 = r8.invoke(r10, r0)     // Catch: java.lang.Throwable -> Lb0
            if (r11 != r1) goto Lab
        Laa:
            return r1
        Lab:
            r8 = r9
        Lac:
            com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f.c(r8, r6)
            return r11
        Lb0:
            r8 = move-exception
            r7 = r9
            r9 = r8
            r8 = r7
        Lb4:
            throw r9     // Catch: java.lang.Throwable -> Lb5
        Lb5:
            r10 = move-exception
            com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f.c(r8, r9)
            throw r10
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.network.okhttp.internal.b.a(okhttp3.A, coil3.network.s, coil3.network.k, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final boolean equals(Object obj) {
        if (obj instanceof b) {
            return this.a.equals(((b) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "CallFactoryNetworkClient(callFactory=" + this.a + ')';
    }
}
