package com.mayakapps.kache;

import kotlin.jvm.internal.Intrinsics;
import okio.AbstractC5085b;

/* loaded from: classes2.dex */
public final class H implements InterfaceC4032a {
    public static final com.quizlet.shared.usecase.folderstudymaterials.d j = new com.quizlet.shared.usecase.folderstudymaterials.d(21);
    public final okio.n a;
    public final okio.x b;
    public final kotlinx.coroutines.C c;
    public final u d;
    public final okio.x e;
    public final kotlinx.coroutines.sync.c f;
    public final okio.x g;
    public com.mayakapps.kache.journal.i h;
    public int i;

    public H(okio.n fileSystem, okio.x directory, long j2, x strategy, kotlinx.coroutines.C creationScope, int i) {
        Intrinsics.checkNotNullParameter(fileSystem, "fileSystem");
        Intrinsics.checkNotNullParameter(directory, "directory");
        Intrinsics.checkNotNullParameter(strategy, "strategy");
        Intrinsics.checkNotNullParameter(creationScope, "creationScope");
        this.a = fileSystem;
        this.b = directory;
        this.c = creationScope;
        this.d = com.google.android.gms.internal.mlkit_vision_document_scanner.H.a(j2, new androidx.compose.ui.viewinterop.b(10, strategy, this));
        this.e = okio.x.f(directory, "files");
        this.f = kotlinx.coroutines.sync.d.a();
        okio.x xVarF = okio.x.f(directory, "journal");
        this.g = xVarF;
        this.h = new com.mayakapps.kache.journal.i(AbstractC5085b.b(fileSystem.a(xVarF, true)));
        this.i = i;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00a3 A[Catch: all -> 0x0034, TryCatch #0 {all -> 0x0034, blocks: (B:13:0x0030, B:38:0x008c, B:39:0x009d, B:41:0x00a3, B:46:0x00bc, B:44:0x00b5, B:47:0x00c0), top: B:52:0x0030 }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /* JADX WARN: Type inference failed for: r9v13, types: [kotlinx.coroutines.sync.a] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object d(com.mayakapps.kache.H r9, kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 243
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.H.d(com.mayakapps.kache.H, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object e(com.mayakapps.kache.H r4, java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4.getClass()
            boolean r0 = r6 instanceof com.mayakapps.kache.G
            if (r0 == 0) goto L16
            r0 = r6
            com.mayakapps.kache.G r0 = (com.mayakapps.kache.G) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.o = r1
            goto L1b
        L16:
            com.mayakapps.kache.G r0 = new com.mayakapps.kache.G
            r0.<init>(r4, r6)
        L1b:
            java.lang.Object r6 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L3a
            if (r2 != r3) goto L32
            kotlinx.coroutines.sync.c r4 = r0.l
            java.lang.String r5 = r0.k
            com.mayakapps.kache.H r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r6 = r4
            r4 = r0
            goto L4e
        L32:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.k = r5
            kotlinx.coroutines.sync.c r6 = r4.f
            r0.l = r6
            r0.o = r3
            java.lang.Object r0 = r6.d(r0)
            if (r0 != r1) goto L4e
            return r1
        L4e:
            r0 = 0
            com.mayakapps.kache.journal.i r1 = r4.h     // Catch: java.lang.Throwable -> L71
            r1.getClass()     // Catch: java.lang.Throwable -> L71
            java.lang.String r2 = "key"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r2)     // Catch: java.lang.Throwable -> L71
            r2 = 64
            r1.i(r2, r5, r0)     // Catch: java.lang.Throwable -> L71
            java.nio.channels.Channel r5 = r1.d     // Catch: java.lang.Throwable -> L71
            okio.z r5 = (okio.z) r5     // Catch: java.lang.Throwable -> L71
            r5.flush()     // Catch: java.lang.Throwable -> L71
            int r5 = r4.i     // Catch: java.lang.Throwable -> L71
            int r5 = r5 + 3
            r4.i = r5     // Catch: java.lang.Throwable -> L71
            kotlin.Unit r4 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L71
            r6.f(r0)
            return r4
        L71:
            r4 = move-exception
            r6.f(r0)
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.H.e(com.mayakapps.kache.H, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:29:0x0084, code lost:
    
        if (r7.a(r0) == r1) goto L30;
     */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0077 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // com.mayakapps.kache.InterfaceC4032a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.h r7) {
        /*
            r6 = this;
            boolean r0 = r7 instanceof com.mayakapps.kache.B
            if (r0 == 0) goto L13
            r0 = r7
            com.mayakapps.kache.B r0 = (com.mayakapps.kache.B) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L1a
        L13:
            com.mayakapps.kache.B r0 = new com.mayakapps.kache.B
            kotlin.coroutines.jvm.internal.c r7 = (kotlin.coroutines.jvm.internal.c) r7
            r0.<init>(r6, r7)
        L1a:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 3
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L45
            if (r2 == r5) goto L3f
            if (r2 == r4) goto L37
            if (r2 != r3) goto L2f
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L87
        L2f:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L37:
            java.util.Iterator r2 = r0.k
            com.mayakapps.kache.H r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L5e
        L3f:
            com.mayakapps.kache.H r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L56
        L45:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r6
            r0.n = r5
            com.mayakapps.kache.u r7 = r6.d
            java.lang.Object r7 = r7.h(r0)
            if (r7 != r1) goto L55
            goto L86
        L55:
            r2 = r6
        L56:
            java.lang.Iterable r7 = (java.lang.Iterable) r7
            java.util.Iterator r7 = r7.iterator()
            r5 = r2
            r2 = r7
        L5e:
            boolean r7 = r2.hasNext()
            if (r7 == 0) goto L77
            java.lang.Object r7 = r2.next()
            java.lang.String r7 = (java.lang.String) r7
            r0.j = r5
            r0.k = r2
            r0.n = r4
            java.lang.Object r7 = r5.f(r7, r0)
            if (r7 != r1) goto L5e
            goto L86
        L77:
            com.mayakapps.kache.u r7 = r5.d
            r2 = 0
            r0.j = r2
            r0.k = r2
            r0.n = r3
            java.lang.Object r7 = r7.a(r0)
            if (r7 != r1) goto L87
        L86:
            return r1
        L87:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.H.a(kotlin.coroutines.h):java.lang.Object");
    }

    @Override // com.mayakapps.kache.InterfaceC4032a
    public final Object b(com.quizlet.shared.cache.k kVar) {
        return this.d.d(kVar);
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x005a, code lost:
    
        if (r7.m(r6, r0) == r1) goto L22;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // com.mayakapps.kache.InterfaceC4032a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(java.lang.String r6, kotlin.coroutines.h r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof com.mayakapps.kache.E
            if (r0 == 0) goto L13
            r0 = r7
            com.mayakapps.kache.E r0 = (com.mayakapps.kache.E) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L1a
        L13:
            com.mayakapps.kache.E r0 = new com.mayakapps.kache.E
            kotlin.coroutines.jvm.internal.c r7 = (kotlin.coroutines.jvm.internal.c) r7
            r0.<init>(r5, r7)
        L1a:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3c
            if (r2 == r4) goto L34
            if (r2 != r3) goto L2c
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L5d
        L2c:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L34:
            java.lang.String r6 = r0.k
            com.mayakapps.kache.H r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4d
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r5
            r0.k = r6
            r0.n = r4
            java.lang.Object r7 = r5.f(r6, r0)
            if (r7 != r1) goto L4c
            goto L5c
        L4c:
            r2 = r5
        L4d:
            com.mayakapps.kache.u r7 = r2.d
            r2 = 0
            r0.j = r2
            r0.k = r2
            r0.n = r3
            java.lang.Object r6 = r7.m(r6, r0)
            if (r6 != r1) goto L5d
        L5c:
            return r1
        L5d:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.H.c(java.lang.String, kotlin.coroutines.h):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object f(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.mayakapps.kache.F
            if (r0 == 0) goto L13
            r0 = r6
            com.mayakapps.kache.F r0 = (com.mayakapps.kache.F) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.mayakapps.kache.F r0 = new com.mayakapps.kache.F
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L37
            if (r2 != r3) goto L2f
            kotlinx.coroutines.sync.c r5 = r0.l
            java.lang.String r1 = r0.k
            com.mayakapps.kache.H r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r6 = r5
            r5 = r1
            goto L4c
        L2f:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.k = r5
            kotlinx.coroutines.sync.c r6 = r4.f
            r0.l = r6
            r0.o = r3
            java.lang.Object r0 = r6.d(r0)
            if (r0 != r1) goto L4b
            return r1
        L4b:
            r0 = r4
        L4c:
            r1 = 0
            com.mayakapps.kache.journal.i r0 = r0.h     // Catch: java.lang.Throwable -> L69
            r0.getClass()     // Catch: java.lang.Throwable -> L69
            java.lang.String r2 = "key"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r2)     // Catch: java.lang.Throwable -> L69
            r2 = 16
            r0.i(r2, r5, r1)     // Catch: java.lang.Throwable -> L69
            java.nio.channels.Channel r5 = r0.d     // Catch: java.lang.Throwable -> L69
            okio.z r5 = (okio.z) r5     // Catch: java.lang.Throwable -> L69
            r5.flush()     // Catch: java.lang.Throwable -> L69
            kotlin.Unit r5 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L69
            r6.f(r1)
            return r5
        L69:
            r5 = move-exception
            r6.f(r1)
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.H.f(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
