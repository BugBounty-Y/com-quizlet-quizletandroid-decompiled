package androidx.glance.session;

import java.util.LinkedHashMap;

/* loaded from: classes.dex */
public final class o {
    public final LinkedHashMap a = new LinkedHashMap();
    public final /* synthetic */ p b;

    public o(p pVar) {
        this.b = pVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(android.content.Context r7, java.lang.String r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r6 = this;
            boolean r0 = r9 instanceof androidx.glance.session.C1235m
            if (r0 == 0) goto L13
            r0 = r9
            androidx.glance.session.m r0 = (androidx.glance.session.C1235m) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.glance.session.m r0 = new androidx.glance.session.m
            r0.<init>(r6, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            java.lang.String r8 = r0.k
            androidx.glance.session.o r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L80
        L2b:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.String r9 = "context"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r9)
            androidx.work.impl.r r7 = androidx.work.impl.r.h(r7)
            java.lang.String r9 = "getInstance(context)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r9)
            androidx.work.impl.WorkDatabase r9 = r7.c
            java.lang.String r2 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r2)
            androidx.work.impl.utils.taskexecutor.c r7 = r7.d
            java.lang.String r2 = "executor"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r2)
            java.lang.String r2 = "name"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r2)
            androidx.compose.foundation.i0 r2 = new androidx.compose.foundation.i0
            r4 = 12
            r2.<init>(r8, r4)
            androidx.appcompat.app.p r7 = r7.a
            java.lang.String r4 = "executor.serialTaskExecutor"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r4)
            androidx.credentials.playservices.controllers.BeginSignIn.d r4 = new androidx.credentials.playservices.controllers.BeginSignIn.d
            r5 = 14
            r4.<init>(r5, r2, r9)
            java.lang.String r9 = "loadStatusFuture"
            androidx.concurrent.futures.l r7 = com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2.h(r7, r9, r4)
            r0.j = r6
            r0.k = r8
            r0.n = r3
            java.lang.Object r9 = com.google.android.gms.internal.mlkit_vision_barcode.Z5.c(r7, r0)
            if (r9 != r1) goto L7f
            return r1
        L7f:
            r7 = r6
        L80:
            java.lang.Iterable r9 = (java.lang.Iterable) r9
            boolean r0 = r9 instanceof java.util.Collection
            r1 = 0
            if (r0 == 0) goto L92
            r0 = r9
            java.util.Collection r0 = (java.util.Collection) r0
            boolean r0 = r0.isEmpty()
            if (r0 == 0) goto L92
        L90:
            r9 = r1
            goto Lb7
        L92:
            java.util.Iterator r9 = r9.iterator()
        L96:
            boolean r0 = r9.hasNext()
            if (r0 == 0) goto L90
            java.lang.Object r0 = r9.next()
            androidx.work.O r0 = (androidx.work.O) r0
            androidx.work.N r2 = androidx.work.N.b
            androidx.work.N r4 = androidx.work.N.a
            androidx.work.N[] r2 = new androidx.work.N[]{r2, r4}
            java.util.List r2 = kotlin.collections.B.j(r2)
            androidx.work.N r0 = r0.b
            boolean r0 = r2.contains(r0)
            if (r0 == 0) goto L96
            r9 = r3
        Lb7:
            java.util.LinkedHashMap r7 = r7.a
            java.lang.Object r7 = r7.get(r8)
            androidx.glance.appwidget.m r7 = (androidx.glance.appwidget.C1182m) r7
            if (r7 == 0) goto Lc8
            java.util.concurrent.atomic.AtomicBoolean r7 = r7.b
            boolean r7 = r7.get()
            goto Lc9
        Lc8:
            r7 = r1
        Lc9:
            if (r7 == 0) goto Lce
            if (r9 == 0) goto Lce
            goto Lcf
        Lce:
            r3 = r1
        Lcf:
            java.lang.Boolean r7 = java.lang.Boolean.valueOf(r3)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.session.o.a(android.content.Context, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x001b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(android.content.Context r21, androidx.glance.appwidget.C1182m r22, kotlin.coroutines.jvm.internal.c r23) {
        /*
            Method dump skipped, instructions count: 318
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.session.o.b(android.content.Context, androidx.glance.appwidget.m, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
