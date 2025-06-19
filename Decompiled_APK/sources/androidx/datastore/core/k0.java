package androidx.datastore.core;

import java.util.concurrent.atomic.AtomicInteger;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class k0 {
    public final kotlinx.coroutines.sync.c a;
    public final androidx.appcompat.app.Q b;
    public final C1087t c;

    public k0(String filePath) {
        Intrinsics.checkNotNullParameter(filePath, "filePath");
        this.a = kotlinx.coroutines.sync.d.a();
        this.b = new androidx.appcompat.app.Q(11);
        this.c = new C1087t(new j0(2, null));
    }

    public final Integer a() {
        return new Integer(((AtomicInteger) this.b.a).get());
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(kotlin.jvm.functions.Function1 r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r7 = this;
            boolean r0 = r9 instanceof androidx.datastore.core.h0
            if (r0 == 0) goto L13
            r0 = r9
            androidx.datastore.core.h0 r0 = (androidx.datastore.core.h0) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.datastore.core.h0 r0 = new androidx.datastore.core.h0
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            r5 = 0
            if (r2 == 0) goto L45
            if (r2 == r4) goto L39
            if (r2 != r3) goto L31
            java.lang.Object r8 = r0.j
            kotlinx.coroutines.sync.a r8 = (kotlinx.coroutines.sync.a) r8
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Throwable -> L2f
            goto L67
        L2f:
            r9 = move-exception
            goto L71
        L31:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L39:
            kotlinx.coroutines.sync.c r8 = r0.k
            java.lang.Object r2 = r0.j
            kotlin.jvm.functions.Function1 r2 = (kotlin.jvm.functions.Function1) r2
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r9 = r8
            r8 = r2
            goto L57
        L45:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r8
            kotlinx.coroutines.sync.c r9 = r7.a
            r0.k = r9
            r0.n = r4
            java.lang.Object r2 = r9.d(r0)
            if (r2 != r1) goto L57
            goto L63
        L57:
            r0.j = r9     // Catch: java.lang.Throwable -> L6d
            r0.k = r5     // Catch: java.lang.Throwable -> L6d
            r0.n = r3     // Catch: java.lang.Throwable -> L6d
            java.lang.Object r8 = r8.invoke(r0)     // Catch: java.lang.Throwable -> L6d
            if (r8 != r1) goto L64
        L63:
            return r1
        L64:
            r6 = r9
            r9 = r8
            r8 = r6
        L67:
            kotlinx.coroutines.sync.c r8 = (kotlinx.coroutines.sync.c) r8
            r8.f(r5)
            return r9
        L6d:
            r8 = move-exception
            r6 = r9
            r9 = r8
            r8 = r6
        L71:
            kotlinx.coroutines.sync.c r8 = (kotlinx.coroutines.sync.c) r8
            r8.f(r5)
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.k0.b(kotlin.jvm.functions.Function1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x0055  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x005f  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(kotlin.jvm.functions.Function2 r7, kotlin.coroutines.jvm.internal.c r8) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r8 instanceof androidx.datastore.core.i0
            if (r0 == 0) goto L13
            r0 = r8
            androidx.datastore.core.i0 r0 = (androidx.datastore.core.i0) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.datastore.core.i0 r0 = new androidx.datastore.core.i0
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            r4 = 0
            if (r2 == 0) goto L36
            if (r2 != r3) goto L2e
            boolean r7 = r0.k
            kotlinx.coroutines.sync.c r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Throwable -> L2c
            goto L53
        L2c:
            r8 = move-exception
            goto L5d
        L2e:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            kotlinx.coroutines.sync.c r8 = r6.a
            boolean r2 = r8.e()
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r2)     // Catch: java.lang.Throwable -> L59
            r0.j = r8     // Catch: java.lang.Throwable -> L59
            r0.k = r2     // Catch: java.lang.Throwable -> L59
            r0.n = r3     // Catch: java.lang.Throwable -> L59
            java.lang.Object r7 = r7.invoke(r5, r0)     // Catch: java.lang.Throwable -> L59
            if (r7 != r1) goto L50
            return r1
        L50:
            r0 = r8
            r8 = r7
            r7 = r2
        L53:
            if (r7 == 0) goto L58
            r0.f(r4)
        L58:
            return r8
        L59:
            r7 = move-exception
            r0 = r8
            r8 = r7
            r7 = r2
        L5d:
            if (r7 == 0) goto L62
            r0.f(r4)
        L62:
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.k0.c(kotlin.jvm.functions.Function2, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
