package androidx.compose.foundation.gestures;

/* loaded from: classes.dex */
public abstract class H {
    public static final float a = ((float) 0.125d) / 18;

    /* JADX WARN: Code restructure failed: missing block: B:46:0x00bf, code lost:
    
        if (androidx.compose.ui.geometry.b.b(androidx.compose.ui.input.pointer.l.g(r11, true), 0) == false) goto L47;
     */
    /* JADX WARN: Removed duplicated region for block: B:20:0x005f A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0060  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0071  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x008b  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0086 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /* JADX WARN: Type inference failed for: r2v9, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r5v5, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:21:0x0060 -> B:22:0x0065). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(androidx.compose.ui.input.pointer.z r17, long r18, kotlin.coroutines.jvm.internal.c r20) {
        /*
            Method dump skipped, instructions count: 205
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.H.a(androidx.compose.ui.input.pointer.z, long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r12v7, types: [java.lang.Object, java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(androidx.compose.ui.input.pointer.z r9, long r10, kotlin.coroutines.jvm.internal.c r12) {
        /*
            boolean r0 = r12 instanceof androidx.compose.foundation.gestures.A
            if (r0 == 0) goto L13
            r0 = r12
            androidx.compose.foundation.gestures.A r0 = (androidx.compose.foundation.gestures.A) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.compose.foundation.gestures.A r0 = new androidx.compose.foundation.gestures.A
            r0.<init>(r12)
        L18:
            java.lang.Object r12 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            r4 = 0
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            kotlin.jvm.internal.J r9 = r0.k
            androidx.compose.ui.input.pointer.n r10 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)     // Catch: androidx.compose.ui.input.pointer.PointerEventTimeoutCancellationException -> L91
            return r4
        L2c:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            androidx.compose.ui.input.pointer.B r12 = r9.f
            androidx.compose.ui.input.pointer.f r12 = r12.r
            boolean r12 = d(r12, r10)
            if (r12 == 0) goto L42
            goto L8f
        L42:
            androidx.compose.ui.input.pointer.B r12 = r9.f
            androidx.compose.ui.input.pointer.f r12 = r12.r
            java.lang.Object r12 = r12.a
            int r2 = r12.size()
            r5 = 0
        L4d:
            if (r5 >= r2) goto L62
            java.lang.Object r6 = r12.get(r5)
            r7 = r6
            androidx.compose.ui.input.pointer.n r7 = (androidx.compose.ui.input.pointer.n) r7
            long r7 = r7.a
            boolean r7 = androidx.compose.ui.input.pointer.m.a(r7, r10)
            if (r7 == 0) goto L5f
            goto L63
        L5f:
            int r5 = r5 + 1
            goto L4d
        L62:
            r6 = r4
        L63:
            r10 = r6
            androidx.compose.ui.input.pointer.n r10 = (androidx.compose.ui.input.pointer.n) r10
            if (r10 != 0) goto L69
            goto L8f
        L69:
            kotlin.jvm.internal.J r11 = new kotlin.jvm.internal.J
            r11.<init>()
            kotlin.jvm.internal.J r12 = new kotlin.jvm.internal.J
            r12.<init>()
            r12.a = r10
            androidx.compose.ui.platform.Y0 r2 = r9.e()
            long r5 = r2.b()
            androidx.compose.foundation.gestures.B r2 = new androidx.compose.foundation.gestures.B     // Catch: androidx.compose.ui.input.pointer.PointerEventTimeoutCancellationException -> L90
            r2.<init>(r12, r11, r4)     // Catch: androidx.compose.ui.input.pointer.PointerEventTimeoutCancellationException -> L90
            r0.j = r10     // Catch: androidx.compose.ui.input.pointer.PointerEventTimeoutCancellationException -> L90
            r0.k = r11     // Catch: androidx.compose.ui.input.pointer.PointerEventTimeoutCancellationException -> L90
            r0.m = r3     // Catch: androidx.compose.ui.input.pointer.PointerEventTimeoutCancellationException -> L90
            java.lang.Object r9 = r9.f(r5, r2, r0)     // Catch: androidx.compose.ui.input.pointer.PointerEventTimeoutCancellationException -> L90
            if (r9 != r1) goto L8f
            return r1
        L8f:
            return r4
        L90:
            r9 = r11
        L91:
            java.lang.Object r9 = r9.a
            androidx.compose.ui.input.pointer.n r9 = (androidx.compose.ui.input.pointer.n) r9
            if (r9 != 0) goto L98
            goto L99
        L98:
            r10 = r9
        L99:
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.H.b(androidx.compose.ui.input.pointer.z, long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0044 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0049  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x004c  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:16:0x0042 -> B:18:0x0045). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object c(androidx.compose.ui.input.pointer.z r4, long r5, kotlin.jvm.functions.Function1 r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            boolean r0 = r8 instanceof androidx.compose.foundation.gestures.G
            if (r0 == 0) goto L13
            r0 = r8
            androidx.compose.foundation.gestures.G r0 = (androidx.compose.foundation.gestures.G) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.compose.foundation.gestures.G r0 = new androidx.compose.foundation.gestures.G
            r0.<init>(r8)
        L18:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            kotlin.jvm.functions.Function1 r4 = r0.k
            androidx.compose.ui.input.pointer.z r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r7 = r4
            r4 = r5
            goto L45
        L2d:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r8)
        L38:
            r0.j = r4
            r0.k = r7
            r0.m = r3
            java.lang.Object r8 = a(r4, r5, r0)
            if (r8 != r1) goto L45
            return r1
        L45:
            androidx.compose.ui.input.pointer.n r8 = (androidx.compose.ui.input.pointer.n) r8
            if (r8 != 0) goto L4c
            java.lang.Boolean r4 = java.lang.Boolean.FALSE
            return r4
        L4c:
            boolean r5 = androidx.compose.ui.input.pointer.l.c(r8)
            if (r5 == 0) goto L55
            java.lang.Boolean r4 = java.lang.Boolean.TRUE
            return r4
        L55:
            r7.invoke(r8)
            long r5 = r8.a
            goto L38
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.H.c(androidx.compose.ui.input.pointer.z, long, kotlin.jvm.functions.Function1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Type inference failed for: r6v1, types: [java.lang.Object, java.util.List] */
    public static final boolean d(androidx.compose.ui.input.pointer.f fVar, long j) {
        Object obj;
        ?? r6 = fVar.a;
        int size = r6.size();
        boolean z = false;
        int i = 0;
        while (true) {
            if (i >= size) {
                obj = null;
                break;
            }
            obj = r6.get(i);
            if (androidx.compose.ui.input.pointer.m.a(((androidx.compose.ui.input.pointer.n) obj).a, j)) {
                break;
            }
            i++;
        }
        androidx.compose.ui.input.pointer.n nVar = (androidx.compose.ui.input.pointer.n) obj;
        if (nVar != null && nVar.d) {
            z = true;
        }
        return true ^ z;
    }
}
