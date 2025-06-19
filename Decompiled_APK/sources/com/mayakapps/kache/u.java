package com.mayakapps.kache;

import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.time.TimeMark;

/* loaded from: classes2.dex */
public final class u {
    public final kotlinx.coroutines.C a;
    public final kotlin.jvm.internal.r b;
    public final kotlin.jvm.internal.r c;
    public final long d;
    public final long e;
    public final com.mayakapps.kache.collection.d f;
    public final kotlinx.coroutines.sync.c g;
    public final androidx.compose.ui.text.android.selection.f h;
    public final androidx.compose.ui.text.android.selection.f i;
    public final com.mayakapps.kache.collection.c j;
    public final kotlinx.coroutines.sync.c k;
    public final long l;
    public long m;
    public final boolean n;
    public final com.mayakapps.kache.collection.b o;

    /* JADX WARN: Multi-variable type inference failed */
    public u(long j, x strategy, kotlinx.coroutines.C creationScope, Function2 sizeCalculator, kotlin.jvm.functions.d onEntryRemoved, kotlin.time.h timeSource, long j2, long j3) {
        Intrinsics.checkNotNullParameter(strategy, "strategy");
        Intrinsics.checkNotNullParameter(creationScope, "creationScope");
        Intrinsics.checkNotNullParameter(sizeCalculator, "sizeCalculator");
        Intrinsics.checkNotNullParameter(onEntryRemoved, "onEntryRemoved");
        Intrinsics.checkNotNullParameter(timeSource, "timeSource");
        this.a = creationScope;
        this.b = (kotlin.jvm.internal.r) sizeCalculator;
        this.c = (kotlin.jvm.internal.r) onEntryRemoved;
        this.d = j2;
        this.e = j3;
        long[] jArr = com.mayakapps.kache.collection.h.a;
        this.f = new com.mayakapps.kache.collection.d(6);
        this.g = kotlinx.coroutines.sync.d.a();
        kotlin.time.b.b.getClass();
        long j4 = kotlin.time.b.c;
        boolean zD = kotlin.time.b.d(j3, j4);
        androidx.compose.ui.text.android.selection.f fVar = null;
        androidx.compose.ui.text.android.selection.f eVar = !zD ? new com.mayakapps.kache.collection.e(timeSource) : (strategy == x.a || strategy == x.b) ? new androidx.compose.ui.text.android.selection.f(8, (byte) 0) : null;
        this.h = eVar;
        if (!kotlin.time.b.d(j2, j4)) {
            fVar = new com.mayakapps.kache.collection.e(timeSource);
        } else if (strategy == x.c || strategy == x.d) {
            fVar = new androidx.compose.ui.text.android.selection.f(8, (byte) 0);
        }
        this.i = fVar;
        com.mayakapps.kache.collection.c cVar = new com.mayakapps.kache.collection.c(eVar, fVar, strategy == x.a || strategy == x.b);
        this.j = cVar;
        this.k = kotlinx.coroutines.sync.d.a();
        this.l = j;
        boolean z = strategy == x.b || strategy == x.d;
        this.n = z;
        this.o = new com.mayakapps.kache.collection.b(cVar, cVar.j, z);
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0082  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x008d A[Catch: all -> 0x007d, TRY_ENTER, TryCatch #1 {all -> 0x007d, blocks: (B:25:0x006b, B:29:0x0079, B:38:0x008d, B:40:0x0095, B:44:0x00d7, B:46:0x00df, B:49:0x00e7, B:50:0x00ee, B:41:0x00b2, B:43:0x00ba, B:34:0x0084), top: B:58:0x006b }] */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00b2 A[Catch: all -> 0x007d, TryCatch #1 {all -> 0x007d, blocks: (B:25:0x006b, B:29:0x0079, B:38:0x008d, B:40:0x0095, B:44:0x00d7, B:46:0x00df, B:49:0x00e7, B:50:0x00ee, B:41:0x00b2, B:43:0x00ba, B:34:0x0084), top: B:58:0x006b }] */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00df A[Catch: all -> 0x007d, TRY_LEAVE, TryCatch #1 {all -> 0x007d, blocks: (B:25:0x006b, B:29:0x0079, B:38:0x008d, B:40:0x0095, B:44:0x00d7, B:46:0x00df, B:49:0x00e7, B:50:0x00ee, B:41:0x00b2, B:43:0x00ba, B:34:0x0084), top: B:58:0x006b }] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00e7 A[Catch: all -> 0x007d, TRY_ENTER, TryCatch #1 {all -> 0x007d, blocks: (B:25:0x006b, B:29:0x0079, B:38:0x008d, B:40:0x0095, B:44:0x00d7, B:46:0x00df, B:49:0x00e7, B:50:0x00ee, B:41:0x00b2, B:43:0x00ba, B:34:0x0084), top: B:58:0x006b }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r3v2, types: [kotlin.jvm.functions.d, kotlin.jvm.internal.r] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.jvm.internal.c r15) {
        /*
            Method dump skipped, instructions count: 248
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.u.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.mayakapps.kache.C4042k
            if (r0 == 0) goto L13
            r0 = r5
            com.mayakapps.kache.k r0 = (com.mayakapps.kache.C4042k) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.mayakapps.kache.k r0 = new com.mayakapps.kache.k
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            kotlinx.coroutines.sync.c r1 = r0.k
            com.mayakapps.kache.u r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L47
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.j = r4
            kotlinx.coroutines.sync.c r5 = r4.k
            r0.k = r5
            r0.n = r3
            java.lang.Object r0 = r5.d(r0)
            if (r0 != r1) goto L45
            return r1
        L45:
            r0 = r4
            r1 = r5
        L47:
            r5 = 0
            r0.j()     // Catch: java.lang.Throwable -> L53
            kotlin.Unit r0 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L53
            r1.f(r5)
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L53:
            r0 = move-exception
            r1.f(r5)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.u.b(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x005f  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0064 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(java.lang.String r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof com.mayakapps.kache.l
            if (r0 == 0) goto L13
            r0 = r7
            com.mayakapps.kache.l r0 = (com.mayakapps.kache.l) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.mayakapps.kache.l r0 = new com.mayakapps.kache.l
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3e
            if (r2 == r4) goto L36
            if (r2 != r3) goto L2e
            java.lang.String r6 = r0.k
            com.mayakapps.kache.u r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L5d
        L2e:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L36:
            java.lang.String r6 = r0.k
            com.mayakapps.kache.u r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4f
        L3e:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r5
            r0.k = r6
            r0.n = r4
            java.lang.Object r7 = r5.b(r0)
            if (r7 != r1) goto L4e
            goto L5b
        L4e:
            r2 = r5
        L4f:
            r0.j = r2
            r0.k = r6
            r0.n = r3
            java.lang.Object r7 = r2.e(r6, r0)
            if (r7 != r1) goto L5c
        L5b:
            return r1
        L5c:
            r0 = r2
        L5d:
            if (r7 != 0) goto L64
            java.lang.Object r6 = r0.g(r6)
            return r6
        L64:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.u.c(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.mayakapps.kache.m
            if (r0 == 0) goto L13
            r0 = r5
            com.mayakapps.kache.m r0 = (com.mayakapps.kache.m) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.mayakapps.kache.m r0 = new com.mayakapps.kache.m
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            kotlinx.coroutines.sync.c r1 = r0.k
            com.mayakapps.kache.u r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L47
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.j = r4
            kotlinx.coroutines.sync.c r5 = r4.k
            r0.k = r5
            r0.n = r3
            java.lang.Object r0 = r5.d(r0)
            if (r0 != r1) goto L45
            return r1
        L45:
            r0 = r4
            r1 = r5
        L47:
            r5 = 0
            r0.j()     // Catch: java.lang.Throwable -> L62
            com.mayakapps.kache.w r2 = new com.mayakapps.kache.w     // Catch: java.lang.Throwable -> L62
            com.mayakapps.kache.collection.b r3 = r0.o     // Catch: java.lang.Throwable -> L62
            java.util.Set r3 = kotlin.collections.CollectionsKt.A0(r3)     // Catch: java.lang.Throwable -> L62
            com.mayakapps.kache.collection.d r0 = r0.f     // Catch: java.lang.Throwable -> L62
            com.mayakapps.kache.collection.g r0 = r0.f     // Catch: java.lang.Throwable -> L62
            java.util.Set r0 = kotlin.collections.CollectionsKt.A0(r0)     // Catch: java.lang.Throwable -> L62
            r2.<init>(r3, r0)     // Catch: java.lang.Throwable -> L62
            r1.f(r5)
            return r2
        L62:
            r0 = move-exception
            r1.f(r5)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.u.d(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final Object e(String str, kotlin.coroutines.jvm.internal.c cVar) {
        kotlinx.coroutines.H h = (kotlinx.coroutines.H) this.f.h(str);
        if (h != null) {
            return f(str, h, cVar);
        }
        return null;
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x0072, code lost:
    
        if (r9 == r1) goto L37;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object f(java.lang.String r7, kotlinx.coroutines.H r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r6 = this;
            boolean r0 = r9 instanceof com.mayakapps.kache.n
            if (r0 == 0) goto L13
            r0 = r9
            com.mayakapps.kache.n r0 = (com.mayakapps.kache.n) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.mayakapps.kache.n r0 = new com.mayakapps.kache.n
            r0.<init>(r6, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3c
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L75
        L2a:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L32:
            java.lang.String r7 = r0.k
            com.mayakapps.kache.u r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.util.concurrent.CancellationException -> L3a
            return r9
        L3a:
            r9 = move-exception
            goto L51
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r6     // Catch: java.util.concurrent.CancellationException -> L4f
            r0.k = r7     // Catch: java.util.concurrent.CancellationException -> L4f
            r0.n = r4     // Catch: java.util.concurrent.CancellationException -> L4f
            java.lang.Object r7 = r8.Y(r0)     // Catch: java.util.concurrent.CancellationException -> L4f
            if (r7 != r1) goto L4c
            goto L74
        L4c:
            return r7
        L4d:
            r8 = r6
            goto L51
        L4f:
            r9 = move-exception
            goto L4d
        L51:
            java.lang.Throwable r9 = r9.getCause()
            boolean r2 = r9 instanceof com.mayakapps.kache.C4033b
            r5 = 0
            if (r2 == 0) goto L76
            com.mayakapps.kache.b r9 = (com.mayakapps.kache.C4033b) r9
            int r9 = r9.a
            if (r9 == r4) goto L68
            if (r9 == r3) goto L63
            goto L76
        L63:
            java.lang.Object r5 = r8.g(r7)
            goto L76
        L68:
            r0.j = r5
            r0.k = r5
            r0.n = r3
            java.lang.Object r9 = r8.e(r7, r0)
            if (r9 != r1) goto L75
        L74:
            return r1
        L75:
            r5 = r9
        L76:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.u.f(java.lang.String, kotlinx.coroutines.H, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x006c, code lost:
    
        if (((r5 & ((~r5) << 6)) & (-9187201950435737472L)) == 0) goto L32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x006e, code lost:
    
        r11 = -1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object g(java.lang.String r15) {
        /*
            Method dump skipped, instructions count: 199
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.u.g(java.lang.String):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object h(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.mayakapps.kache.o
            if (r0 == 0) goto L13
            r0 = r5
            com.mayakapps.kache.o r0 = (com.mayakapps.kache.o) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.mayakapps.kache.o r0 = new com.mayakapps.kache.o
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            kotlinx.coroutines.sync.c r1 = r0.k
            com.mayakapps.kache.u r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L47
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.j = r4
            kotlinx.coroutines.sync.c r5 = r4.k
            r0.k = r5
            r0.n = r3
            java.lang.Object r0 = r5.d(r0)
            if (r0 != r1) goto L45
            return r1
        L45:
            r0 = r4
            r1 = r5
        L47:
            r5 = 0
            r0.j()     // Catch: java.lang.Throwable -> L55
            com.mayakapps.kache.collection.b r0 = r0.o     // Catch: java.lang.Throwable -> L55
            java.util.Set r0 = kotlin.collections.CollectionsKt.A0(r0)     // Catch: java.lang.Throwable -> L55
            r1.f(r5)
            return r0
        L55:
            r0 = move-exception
            r1.f(r5)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.u.h(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:37:0x009d A[Catch: all -> 0x0046, TryCatch #0 {all -> 0x0046, blocks: (B:19:0x0041, B:45:0x00d6, B:35:0x0095, B:37:0x009d, B:39:0x00a5, B:41:0x00ca, B:42:0x00cb), top: B:52:0x0023 }] */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00d6 A[Catch: all -> 0x0046, PHI: r2 r10 r11
  0x00d6: PHI (r2v4 com.mayakapps.kache.u) = (r2v3 com.mayakapps.kache.u), (r2v3 com.mayakapps.kache.u), (r2v3 com.mayakapps.kache.u), (r2v8 com.mayakapps.kache.u) binds: [B:36:0x009b, B:38:0x00a3, B:43:0x00d3, B:19:0x0041] A[DONT_GENERATE, DONT_INLINE]
  0x00d6: PHI (r10v6 ??) = (r10v15 ??), (r10v16 ??), (r10v17 ??), (r10v18 ??) binds: [B:36:0x009b, B:38:0x00a3, B:43:0x00d3, B:19:0x0041] A[DONT_GENERATE, DONT_INLINE]
  0x00d6: PHI (r11v5 java.lang.String) = (r11v4 java.lang.String), (r11v4 java.lang.String), (r11v4 java.lang.String), (r11v11 java.lang.String) binds: [B:36:0x009b, B:38:0x00a3, B:43:0x00d3, B:19:0x0041] A[DONT_GENERATE, DONT_INLINE], TRY_LEAVE, TryCatch #0 {all -> 0x0046, blocks: (B:19:0x0041, B:45:0x00d6, B:35:0x0095, B:37:0x009d, B:39:0x00a5, B:41:0x00ca, B:42:0x00cb), top: B:52:0x0023 }] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00ee A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r10v0, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r10v1 */
    /* JADX WARN: Type inference failed for: r10v15 */
    /* JADX WARN: Type inference failed for: r10v16 */
    /* JADX WARN: Type inference failed for: r10v17 */
    /* JADX WARN: Type inference failed for: r10v18 */
    /* JADX WARN: Type inference failed for: r10v6 */
    /* JADX WARN: Type inference failed for: r11v7, types: [kotlin.jvm.functions.Function2] */
    /* JADX WARN: Type inference failed for: r11v9, types: [kotlin.jvm.functions.Function2] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object i(java.lang.String r10, com.mayakapps.kache.J r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            Method dump skipped, instructions count: 245
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.u.i(java.lang.String, com.mayakapps.kache.J, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [kotlin.jvm.functions.d, kotlin.jvm.internal.r] */
    public final void j() {
        androidx.compose.ui.text.android.selection.f fVar = this.h;
        com.mayakapps.kache.collection.e eVar = fVar instanceof com.mayakapps.kache.collection.e ? (com.mayakapps.kache.collection.e) fVar : null;
        ?? r1 = this.c;
        com.mayakapps.kache.collection.c cVar = this.j;
        if (eVar != null) {
            androidx.compose.ui.text.android.selection.f fVar2 = cVar.h;
            if (fVar2 == null) {
                fVar2 = cVar.i;
                Intrinsics.d(fVar2);
            }
            int i = fVar2.b;
            int[] iArr = (int[]) fVar2.d;
            while (i != -1) {
                int i2 = iArr[i];
                Object obj = cVar.b[i];
                Object obj2 = cVar.c[i];
                TimeMark timeMark = eVar.g[i];
                Intrinsics.d(timeMark);
                if (kotlin.time.b.c(timeMark.a(), this.e) < 0) {
                    break;
                }
                cVar.l(i);
                this.m -= p(obj, obj2);
                r1.invoke(Boolean.TRUE, obj, obj2, null);
                i = i2;
            }
        }
        androidx.compose.ui.text.android.selection.f fVar3 = this.i;
        com.mayakapps.kache.collection.e eVar2 = fVar3 instanceof com.mayakapps.kache.collection.e ? (com.mayakapps.kache.collection.e) fVar3 : null;
        if (eVar2 != null) {
            androidx.compose.ui.text.android.selection.f fVar4 = cVar.i;
            if (fVar4 == null) {
                fVar4 = cVar.h;
                Intrinsics.d(fVar4);
            }
            int i3 = fVar4.b;
            int[] iArr2 = (int[]) fVar4.d;
            while (i3 != -1) {
                int i4 = iArr2[i3];
                Object obj3 = cVar.b[i3];
                Object obj4 = cVar.c[i3];
                TimeMark timeMark2 = eVar2.g[i3];
                Intrinsics.d(timeMark2);
                if (kotlin.time.b.c(timeMark2.a(), this.d) < 0) {
                    break;
                }
                cVar.l(i3);
                this.m -= p(obj3, obj4);
                r1.invoke(Boolean.TRUE, obj3, obj4, null);
                i3 = i4;
            }
        }
        long j = this.m;
        if (j < 0) {
            if (cVar.e != 0 || j == 0) {
                throw new IllegalStateException("sizeCalculator is reporting inconsistent results!");
            }
        }
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [kotlin.jvm.functions.d, kotlin.jvm.internal.r] */
    public final void k(long j) {
        if (this.m <= j) {
            return;
        }
        com.mayakapps.kache.collection.c cVar = this.j;
        boolean z = cVar.j;
        androidx.compose.ui.text.android.selection.f fVar = cVar.i;
        androidx.compose.ui.text.android.selection.f fVar2 = cVar.h;
        if (z) {
            if (fVar2 == null) {
                Intrinsics.d(fVar);
            } else {
                fVar = fVar2;
            }
        } else if (fVar == null) {
            Intrinsics.d(fVar2);
            fVar = fVar2;
        }
        ?? r1 = this.c;
        if (this.n) {
            int i = fVar.c;
            int[] iArr = (int[]) fVar.e;
            while (i != -1) {
                int i2 = iArr[i];
                Object obj = cVar.b[i];
                Object obj2 = cVar.c[i];
                if (this.m <= j) {
                    break;
                }
                cVar.l(i);
                this.m -= p(obj, obj2);
                r1.invoke(Boolean.TRUE, obj, obj2, null);
                i = i2;
            }
        } else {
            int i3 = fVar.b;
            int[] iArr2 = (int[]) fVar.d;
            while (i3 != -1) {
                int i4 = iArr2[i3];
                Object obj3 = cVar.b[i3];
                Object obj4 = cVar.c[i3];
                if (this.m <= j) {
                    break;
                }
                cVar.l(i3);
                this.m -= p(obj3, obj4);
                r1.invoke(Boolean.TRUE, obj3, obj4, null);
                i3 = i4;
            }
        }
        long j2 = this.m;
        if (j2 < 0) {
            if (cVar.e != 0 || j2 == 0) {
                throw new IllegalStateException("sizeCalculator is reporting inconsistent results!");
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:39:0x00ee, code lost:
    
        if (r8.q(r4, r2) == r3) goto L40;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /* JADX WARN: Type inference failed for: r10v1, types: [kotlin.jvm.functions.d, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r7v4, types: [java.util.Map] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object l(java.util.LinkedHashMap r21, kotlin.coroutines.jvm.internal.c r22) {
        /*
            Method dump skipped, instructions count: 248
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.u.l(java.util.LinkedHashMap, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x007e A[Catch: all -> 0x0088, TryCatch #0 {all -> 0x0088, blocks: (B:25:0x0076, B:27:0x007e, B:30:0x008a), top: B:41:0x0076 }] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0092  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x009a A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r0v6, types: [kotlin.jvm.functions.d, kotlin.jvm.internal.r] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object m(java.lang.Object r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            r8 = this;
            boolean r0 = r10 instanceof com.mayakapps.kache.s
            if (r0 == 0) goto L13
            r0 = r10
            com.mayakapps.kache.s r0 = (com.mayakapps.kache.s) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.mayakapps.kache.s r0 = new com.mayakapps.kache.s
            r0.<init>(r8, r10)
        L18:
            java.lang.Object r10 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 0
            r4 = 1
            r5 = 2
            if (r2 == 0) goto L45
            if (r2 == r4) goto L39
            if (r2 != r5) goto L31
            kotlinx.coroutines.sync.c r9 = r0.l
            java.lang.Object r1 = r0.k
            com.mayakapps.kache.u r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L76
        L31:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L39:
            kotlinx.coroutines.sync.c r9 = r0.l
            java.lang.Object r2 = r0.k
            com.mayakapps.kache.u r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            r10 = r9
            r9 = r2
            goto L5a
        L45:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            r0.j = r8
            r0.k = r9
            kotlinx.coroutines.sync.c r10 = r8.g
            r0.l = r10
            r0.o = r4
            java.lang.Object r2 = r10.d(r0)
            if (r2 != r1) goto L59
            goto L72
        L59:
            r4 = r8
        L5a:
            r4.o(r3, r9)     // Catch: java.lang.Throwable -> L9f
            kotlin.Unit r2 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L9f
            r10.f(r3)
            r0.j = r4
            r0.k = r9
            kotlinx.coroutines.sync.c r10 = r4.k
            r0.l = r10
            r0.o = r5
            java.lang.Object r0 = r10.d(r0)
            if (r0 != r1) goto L73
        L72:
            return r1
        L73:
            r1 = r9
            r9 = r10
            r0 = r4
        L76:
            com.mayakapps.kache.collection.c r10 = r0.j     // Catch: java.lang.Throwable -> L88
            java.lang.Object r10 = r10.k(r1)     // Catch: java.lang.Throwable -> L88
            if (r10 == 0) goto L8a
            long r4 = r0.m     // Catch: java.lang.Throwable -> L88
            long r6 = r0.p(r1, r10)     // Catch: java.lang.Throwable -> L88
            long r4 = r4 - r6
            r0.m = r4     // Catch: java.lang.Throwable -> L88
            goto L8a
        L88:
            r10 = move-exception
            goto L9b
        L8a:
            r0.j()     // Catch: java.lang.Throwable -> L88
            r9.f(r3)
            if (r10 == 0) goto L9a
            java.lang.Boolean r9 = java.lang.Boolean.FALSE
            kotlin.jvm.internal.r r0 = r0.c
            r0.invoke(r9, r1, r10, r3)
            return r10
        L9a:
            return r3
        L9b:
            r9.f(r3)
            throw r10
        L9f:
            r9 = move-exception
            r10.f(r3)
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.u.m(java.lang.Object, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void n() {
        com.mayakapps.kache.collection.d dVar = this.f;
        Object[] objArr = dVar.b;
        if (dVar instanceof com.mayakapps.kache.collection.c) {
            androidx.compose.ui.text.android.selection.f fVar = ((com.mayakapps.kache.collection.c) dVar).k;
            int i = fVar.b;
            int[] iArr = (int[]) fVar.d;
            while (i != -1) {
                int i2 = iArr[i];
                o(null, objArr[i]);
                i = i2;
            }
            return;
        }
        long[] jArr = dVar.a;
        int length = jArr.length - 2;
        if (length < 0) {
            return;
        }
        int i3 = 0;
        while (true) {
            long j = jArr[i3];
            if ((((~j) << 7) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                int i4 = 8 - ((~(i3 - length)) >>> 31);
                for (int i5 = 0; i5 < i4; i5++) {
                    if ((255 & j) < 128) {
                        o(null, objArr[(i3 << 3) + i5]);
                    }
                    j >>= 8;
                }
                if (i4 != 8) {
                    return;
                }
            }
            if (i3 == length) {
                return;
            } else {
                i3++;
            }
        }
    }

    public final void o(Integer num, Object obj) {
        kotlinx.coroutines.H h = (kotlinx.coroutines.H) this.f.k(obj);
        if (h != null) {
            kotlinx.coroutines.E.j(h, "The cached element was removed before creation", num != null ? new C4033b(num.intValue()) : null);
        }
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.Function2, kotlin.jvm.internal.r] */
    public final long p(Object obj, Object obj2) {
        long jLongValue = ((Number) this.b.invoke(obj, obj2)).longValue();
        if (jLongValue >= 0) {
            return jLongValue;
        }
        throw new IllegalStateException(("Negative size: " + obj + " = " + obj2).toString());
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object q(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.mayakapps.kache.t
            if (r0 == 0) goto L13
            r0 = r7
            com.mayakapps.kache.t r0 = (com.mayakapps.kache.t) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.mayakapps.kache.t r0 = new com.mayakapps.kache.t
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            long r5 = r0.l
            kotlinx.coroutines.sync.c r1 = r0.k
            com.mayakapps.kache.u r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4b
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r4
            kotlinx.coroutines.sync.c r7 = r4.k
            r0.k = r7
            r0.l = r5
            r0.o = r3
            java.lang.Object r0 = r7.d(r0)
            if (r0 != r1) goto L49
            return r1
        L49:
            r0 = r4
            r1 = r7
        L4b:
            r7 = 0
            r0.j()     // Catch: java.lang.Throwable -> L5a
            r0.k(r5)     // Catch: java.lang.Throwable -> L5a
            kotlin.Unit r5 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L5a
            r1.f(r7)
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L5a:
            r5 = move-exception
            r1.f(r7)
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.u.q(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
