package androidx.glance.state;

import java.util.LinkedHashMap;

/* loaded from: classes.dex */
public final class f implements a {
    public static final f a = new f();
    public static final kotlinx.coroutines.sync.c b = kotlinx.coroutines.sync.d.a();
    public static final LinkedHashMap c = new LinkedHashMap();

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r6v3, types: [androidx.glance.state.g] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(android.content.Context r5, androidx.glance.state.h r6, java.lang.String r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r4 = this;
            boolean r0 = r8 instanceof androidx.glance.state.b
            if (r0 == 0) goto L13
            r0 = r8
            androidx.glance.state.b r0 = (androidx.glance.state.b) r0
            int r1 = r0.p
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.p = r1
            goto L18
        L13:
            androidx.glance.state.b r0 = new androidx.glance.state.b
            r0.<init>(r4, r8)
        L18:
            java.lang.Object r8 = r0.n
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.p
            r3 = 1
            if (r2 == 0) goto L39
            if (r2 != r3) goto L31
            kotlinx.coroutines.sync.c r5 = r0.m
            java.lang.String r7 = r0.l
            androidx.glance.state.g r6 = r0.k
            android.content.Context r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r8 = r5
            r5 = r0
            goto L4f
        L31:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L39:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r5
            r0.k = r6
            r0.l = r7
            kotlinx.coroutines.sync.c r8 = androidx.glance.state.f.b
            r0.m = r8
            r0.p = r3
            java.lang.Object r0 = r8.d(r0)
            if (r0 != r1) goto L4f
            return r1
        L4f:
            r0 = 0
            java.util.LinkedHashMap r1 = androidx.glance.state.f.c     // Catch: java.lang.Throwable -> L62
            r1.remove(r7)     // Catch: java.lang.Throwable -> L62
            java.io.File r5 = r6.a(r5, r7)     // Catch: java.lang.Throwable -> L62
            r5.delete()     // Catch: java.lang.Throwable -> L62
            r8.f(r0)
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L62:
            r5 = move-exception
            r8.f(r0)
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.state.f.a(android.content.Context, androidx.glance.state.h, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(android.content.Context r7, androidx.glance.state.g r8, java.lang.String r9, kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r10 instanceof androidx.glance.state.c
            if (r0 == 0) goto L13
            r0 = r10
            androidx.glance.state.c r0 = (androidx.glance.state.c) r0
            int r1 = r0.p
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.p = r1
            goto L18
        L13:
            androidx.glance.state.c r0 = new androidx.glance.state.c
            r0.<init>(r6, r10)
        L18:
            java.lang.Object r10 = r0.n
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.p
            r3 = 2
            r4 = 1
            r5 = 0
            if (r2 == 0) goto L57
            if (r2 == r4) goto L42
            if (r2 != r3) goto L3a
            java.io.Serializable r7 = r0.l
            java.util.Map r7 = (java.util.Map) r7
            java.lang.Object r8 = r0.k
            kotlinx.coroutines.sync.a r8 = (kotlinx.coroutines.sync.a) r8
            java.lang.Object r9 = r0.j
            java.lang.String r9 = (java.lang.String) r9
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Throwable -> L37
            goto L89
        L37:
            r7 = move-exception
            goto La1
        L3a:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L42:
            kotlinx.coroutines.sync.c r7 = r0.m
            java.io.Serializable r8 = r0.l
            r9 = r8
            java.lang.String r9 = (java.lang.String) r9
            java.lang.Object r8 = r0.k
            androidx.glance.state.g r8 = (androidx.glance.state.g) r8
            java.lang.Object r2 = r0.j
            android.content.Context r2 = (android.content.Context) r2
            androidx.glance.appwidget.protobuf.Z.e(r10)
            r10 = r7
            r7 = r2
            goto L6d
        L57:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            r0.j = r7
            r0.k = r8
            r0.l = r9
            kotlinx.coroutines.sync.c r10 = androidx.glance.state.f.b
            r0.m = r10
            r0.p = r4
            java.lang.Object r2 = r10.d(r0)
            if (r2 != r1) goto L6d
            goto L85
        L6d:
            java.util.LinkedHashMap r2 = androidx.glance.state.f.c     // Catch: java.lang.Throwable -> L90
            java.lang.Object r4 = r2.get(r9)     // Catch: java.lang.Throwable -> L90
            if (r4 != 0) goto L93
            r0.j = r9     // Catch: java.lang.Throwable -> L90
            r0.k = r10     // Catch: java.lang.Throwable -> L90
            r0.l = r2     // Catch: java.lang.Throwable -> L90
            r0.m = r5     // Catch: java.lang.Throwable -> L90
            r0.p = r3     // Catch: java.lang.Throwable -> L90
            java.lang.Object r7 = r8.b(r7, r9)     // Catch: java.lang.Throwable -> L90
            if (r7 != r1) goto L86
        L85:
            return r1
        L86:
            r8 = r10
            r10 = r7
            r7 = r2
        L89:
            r4 = r10
            androidx.datastore.core.h r4 = (androidx.datastore.core.InterfaceC1076h) r4     // Catch: java.lang.Throwable -> L37
            r7.put(r9, r4)     // Catch: java.lang.Throwable -> L37
            goto L94
        L90:
            r7 = move-exception
            r8 = r10
            goto La1
        L93:
            r8 = r10
        L94:
            java.lang.String r7 = "null cannot be cast to non-null type androidx.datastore.core.DataStore<T of androidx.glance.state.GlanceState.getDataStore$lambda$2>"
            kotlin.jvm.internal.Intrinsics.e(r4, r7)     // Catch: java.lang.Throwable -> L37
            androidx.datastore.core.h r4 = (androidx.datastore.core.InterfaceC1076h) r4     // Catch: java.lang.Throwable -> L37
            kotlinx.coroutines.sync.c r8 = (kotlinx.coroutines.sync.c) r8
            r8.f(r5)
            return r4
        La1:
            kotlinx.coroutines.sync.c r8 = (kotlinx.coroutines.sync.c) r8
            r8.f(r5)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.state.f.b(android.content.Context, androidx.glance.state.g, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(android.content.Context r6, androidx.glance.state.g r7, java.lang.String r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r5 = this;
            boolean r0 = r9 instanceof androidx.glance.state.d
            if (r0 == 0) goto L13
            r0 = r9
            androidx.glance.state.d r0 = (androidx.glance.state.d) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            androidx.glance.state.d r0 = new androidx.glance.state.d
            r0.<init>(r5, r9)
        L18:
            java.lang.Object r9 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L36
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r9)
            return r9
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L42
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.l = r4
            java.lang.Object r9 = r5.b(r6, r7, r8, r0)
            if (r9 != r1) goto L42
            goto L50
        L42:
            androidx.datastore.core.h r9 = (androidx.datastore.core.InterfaceC1076h) r9
            kotlinx.coroutines.flow.i r6 = r9.getData()
            r0.l = r3
            java.lang.Object r6 = kotlinx.coroutines.flow.e0.p(r6, r0)
            if (r6 != r1) goto L51
        L50:
            return r1
        L51:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.state.f.c(android.content.Context, androidx.glance.state.g, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r5v0, types: [androidx.glance.state.f] */
    /* JADX WARN: Type inference failed for: r9v2, types: [kotlin.jvm.functions.Function2] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(android.content.Context r6, androidx.glance.appwidget.t0 r7, java.lang.String r8, androidx.glance.appwidget.C1183m0 r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            r5 = this;
            boolean r0 = r10 instanceof androidx.glance.state.e
            if (r0 == 0) goto L13
            r0 = r10
            androidx.glance.state.e r0 = (androidx.glance.state.e) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.glance.state.e r0 = new androidx.glance.state.e
            r0.<init>(r5, r10)
        L18:
            java.lang.Object r10 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r10)
            return r10
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            kotlin.jvm.functions.Function2 r9 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L46
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            r0.j = r9
            r0.m = r4
            java.lang.Object r10 = r5.b(r6, r7, r8, r0)
            if (r10 != r1) goto L46
            goto L53
        L46:
            androidx.datastore.core.h r10 = (androidx.datastore.core.InterfaceC1076h) r10
            r6 = 0
            r0.j = r6
            r0.m = r3
            java.lang.Object r6 = r10.a(r9, r0)
            if (r6 != r1) goto L54
        L53:
            return r1
        L54:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.state.f.d(android.content.Context, androidx.glance.appwidget.t0, java.lang.String, androidx.glance.appwidget.m0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
