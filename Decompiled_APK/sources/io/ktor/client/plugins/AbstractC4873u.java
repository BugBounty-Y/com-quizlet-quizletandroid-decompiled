package io.ktor.client.plugins;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3189k7;
import com.google.android.gms.internal.mlkit_vision_barcode.V6;
import kotlin.jvm.internal.C4950i;

/* renamed from: io.ktor.client.plugins.u, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4873u {
    public static final org.slf4j.b a = AbstractC3189k7.d("io.ktor.client.plugins.HttpCallValidator");
    public static final io.ktor.client.plugins.api.d b = V6.a("HttpResponseValidator", C4868o.a, new com.sdk.growthbook.utils.a(9));
    public static final io.ktor.util.a c;

    static {
        kotlin.jvm.internal.U uC;
        C4950i c4950iA = kotlin.jvm.internal.K.a(Boolean.class);
        try {
            uC = kotlin.jvm.internal.K.c(Boolean.TYPE);
        } catch (Throwable unused) {
            uC = null;
        }
        c = new io.ktor.util.a("ExpectSuccessAttributeKey", new io.ktor.util.reflect.a(c4950iA, uC));
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final kotlin.Unit a(java.util.List r4, java.lang.Throwable r5, io.ktor.client.request.b r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            boolean r0 = r7 instanceof io.ktor.client.plugins.r
            if (r0 == 0) goto L13
            r0 = r7
            io.ktor.client.plugins.r r0 = (io.ktor.client.plugins.r) r0
            int r1 = r0.k
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.k = r1
            goto L18
        L13:
            io.ktor.client.plugins.r r0 = new io.ktor.client.plugins.r
            r0.<init>(r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r0 = r0.k
            if (r0 == 0) goto L34
            r4 = 1
            if (r0 == r4) goto L26
            r4 = 2
            if (r0 != r4) goto L2a
        L26:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L32
        L2a:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L32:
            r4 = 0
            goto L5a
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.StringBuilder r7 = new java.lang.StringBuilder
            java.lang.String r0 = "Processing exception "
            r7.<init>(r0)
            r7.append(r5)
            java.lang.String r5 = " for request "
            r7.append(r5)
            io.ktor.http.A r5 = r6.i()
            r7.append(r5)
            java.lang.String r5 = r7.toString()
            org.slf4j.b r6 = io.ktor.client.plugins.AbstractC4873u.a
            r6.n(r5)
            java.util.Iterator r4 = r4.iterator()
        L5a:
            boolean r5 = r4.hasNext()
            if (r5 != 0) goto L63
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        L63:
            java.lang.Object r4 = r4.next()
            if (r4 != 0) goto L6f
            kotlin.NoWhenBranchMatchedException r4 = new kotlin.NoWhenBranchMatchedException
            r4.<init>()
            throw r4
        L6f:
            java.lang.ClassCastException r4 = new java.lang.ClassCastException
            r4.<init>()
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.AbstractC4873u.a(java.util.List, java.lang.Throwable, io.ktor.client.request.b, kotlin.coroutines.jvm.internal.c):kotlin.Unit");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(java.util.List r4, io.ktor.client.statement.b r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            boolean r0 = r6 instanceof io.ktor.client.plugins.C4871s
            if (r0 == 0) goto L13
            r0 = r6
            io.ktor.client.plugins.s r0 = (io.ktor.client.plugins.C4871s) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            io.ktor.client.plugins.s r0 = new io.ktor.client.plugins.s
            r0.<init>(r6)
        L18:
            java.lang.Object r6 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            java.util.Iterator r4 = r0.k
            io.ktor.client.statement.b r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L59
        L2b:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.StringBuilder r6 = new java.lang.StringBuilder
            java.lang.String r2 = "Validating response for request "
            r6.<init>(r2)
            io.ktor.client.call.b r2 = r5.b()
            io.ktor.client.request.b r2 = r2.c()
            io.ktor.http.A r2 = r2.i()
            r6.append(r2)
            java.lang.String r6 = r6.toString()
            org.slf4j.b r2 = io.ktor.client.plugins.AbstractC4873u.a
            r2.n(r6)
            java.util.Iterator r4 = r4.iterator()
        L59:
            boolean r6 = r4.hasNext()
            if (r6 == 0) goto L72
            java.lang.Object r6 = r4.next()
            kotlin.jvm.functions.Function2 r6 = (kotlin.jvm.functions.Function2) r6
            r0.j = r5
            r0.k = r4
            r0.m = r3
            java.lang.Object r6 = r6.invoke(r5, r0)
            if (r6 != r1) goto L59
            return r1
        L72:
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.AbstractC4873u.b(java.util.List, io.ktor.client.statement.b, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
