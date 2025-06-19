package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class k1 {
    public static final S a = new S(3, 2, null);

    /* JADX WARN: Removed duplicated region for block: B:17:0x0040 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:20:0x004d A[LOOP:0: B:19:0x004b->B:20:0x004d, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r9v6, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:16:0x003e -> B:18:0x0041). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(androidx.compose.ui.input.pointer.z r8, kotlin.coroutines.jvm.internal.a r9) {
        /*
            boolean r0 = r9 instanceof androidx.compose.foundation.gestures.O0
            if (r0 == 0) goto L13
            r0 = r9
            androidx.compose.foundation.gestures.O0 r0 = (androidx.compose.foundation.gestures.O0) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            androidx.compose.foundation.gestures.O0 r0 = new androidx.compose.foundation.gestures.O0
            r0.<init>(r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.compose.ui.input.pointer.z r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L41
        L29:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r9)
        L34:
            r0.j = r8
            r0.l = r3
            androidx.compose.ui.input.pointer.g r9 = androidx.compose.ui.input.pointer.g.b
            java.lang.Object r9 = r8.c(r9, r0)
            if (r9 != r1) goto L41
            return r1
        L41:
            androidx.compose.ui.input.pointer.f r9 = (androidx.compose.ui.input.pointer.f) r9
            java.lang.Object r2 = r9.a
            int r4 = r2.size()
            r5 = 0
            r6 = r5
        L4b:
            if (r6 >= r4) goto L59
            java.lang.Object r7 = r2.get(r6)
            androidx.compose.ui.input.pointer.n r7 = (androidx.compose.ui.input.pointer.n) r7
            r7.a()
            int r6 = r6 + 1
            goto L4b
        L59:
            java.lang.Object r9 = r9.a
            int r2 = r9.size()
        L5f:
            if (r5 >= r2) goto L6f
            java.lang.Object r4 = r9.get(r5)
            androidx.compose.ui.input.pointer.n r4 = (androidx.compose.ui.input.pointer.n) r4
            boolean r4 = r4.d
            if (r4 == 0) goto L6c
            goto L34
        L6c:
            int r5 = r5 + 1
            goto L5f
        L6f:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.k1.a(androidx.compose.ui.input.pointer.z, kotlin.coroutines.jvm.internal.a):java.lang.Object");
    }

    /*  JADX ERROR: JadxOverflowException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxOverflowException: Regions count limit reached
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        */
    /* JADX WARN: Removed duplicated region for block: B:17:0x004a A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0057  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x007c A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r10v3, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:16:0x0048 -> B:18:0x004b). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(androidx.compose.ui.input.pointer.z r10, boolean r11, androidx.compose.ui.input.pointer.g r12, kotlin.coroutines.jvm.internal.a r13) {
        /*
            boolean r0 = r13 instanceof androidx.compose.foundation.gestures.M0
            if (r0 == 0) goto L13
            r0 = r13
            androidx.compose.foundation.gestures.M0 r0 = (androidx.compose.foundation.gestures.M0) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.compose.foundation.gestures.M0 r0 = new androidx.compose.foundation.gestures.M0
            r0.<init>(r13)
        L18:
            java.lang.Object r13 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L39
            if (r2 != r3) goto L31
            boolean r10 = r0.l
            androidx.compose.ui.input.pointer.g r11 = r0.k
            androidx.compose.ui.input.pointer.z r12 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r9 = r11
            r11 = r10
            r10 = r12
            r12 = r9
            goto L4b
        L31:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L39:
            androidx.glance.appwidget.protobuf.Z.e(r13)
        L3c:
            r0.j = r10
            r0.k = r12
            r0.l = r11
            r0.n = r3
            java.lang.Object r13 = r10.c(r12, r0)
            if (r13 != r1) goto L4b
            return r1
        L4b:
            androidx.compose.ui.input.pointer.f r13 = (androidx.compose.ui.input.pointer.f) r13
            java.lang.Object r2 = r13.a
            int r4 = r2.size()
            r5 = 0
            r6 = r5
        L55:
            if (r6 >= r4) goto L7c
            java.lang.Object r7 = r2.get(r6)
            androidx.compose.ui.input.pointer.n r7 = (androidx.compose.ui.input.pointer.n) r7
            if (r11 == 0) goto L71
            boolean r8 = r7.b()
            if (r8 != 0) goto L6f
            boolean r8 = r7.h
            if (r8 != 0) goto L6f
            boolean r7 = r7.d
            if (r7 == 0) goto L6f
            r7 = r3
            goto L75
        L6f:
            r7 = r5
            goto L75
        L71:
            boolean r7 = androidx.compose.ui.input.pointer.l.a(r7)
        L75:
            if (r7 != 0) goto L79
            r2 = r5
            goto L7d
        L79:
            int r6 = r6 + 1
            goto L55
        L7c:
            r2 = r3
        L7d:
            if (r2 == 0) goto L3c
            java.lang.Object r10 = r13.a
            java.lang.Object r10 = r10.get(r5)
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.k1.b(androidx.compose.ui.input.pointer.z, boolean, androidx.compose.ui.input.pointer.g, kotlin.coroutines.jvm.internal.a):java.lang.Object");
    }

    public static Object d(androidx.compose.ui.input.pointer.B b, Function1 function1, Function1 function12, kotlin.coroutines.jvm.internal.i iVar, int i) {
        Object objM = kotlinx.coroutines.E.m(new i1(b, a, (i & 2) != 0 ? null : function1, null, (i & 8) != 0 ? null : function12, null), iVar);
        return objM == kotlin.coroutines.intrinsics.a.a ? objM : Unit.a;
    }

    /* JADX WARN: Code restructure failed: missing block: B:27:0x007f, code lost:
    
        r0 = r11.size();
        r8 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x0084, code lost:
    
        if (r8 >= r0) goto L54;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x0086, code lost:
    
        r9 = (androidx.compose.ui.input.pointer.n) r11.get(r8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x0090, code lost:
    
        if (r9.b() != false) goto L55;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x009e, code lost:
    
        if (androidx.compose.ui.input.pointer.l.e(r9, r7.f.v, r7.d()) == false) goto L34;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x00a1, code lost:
    
        r8 = r8 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00a4, code lost:
    
        r0 = androidx.compose.ui.input.pointer.g.c;
        r1.j = r7;
        r1.k = r3;
        r1.m = 2;
        r0 = r7.c(r0, r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00b0, code lost:
    
        if (r0 != r2) goto L13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:?, code lost:
    
        return null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:?, code lost:
    
        return null;
     */
    /* JADX WARN: Removed duplicated region for block: B:21:0x005c  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00d5 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0015  */
    /* JADX WARN: Type inference failed for: r0v15, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r11v0, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r8v0, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:36:0x00b0 -> B:13:0x0030). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object e(androidx.compose.ui.input.pointer.z r17, androidx.compose.ui.input.pointer.g r18, kotlin.coroutines.jvm.internal.a r19) {
        /*
            Method dump skipped, instructions count: 218
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.k1.e(androidx.compose.ui.input.pointer.z, androidx.compose.ui.input.pointer.g, kotlin.coroutines.jvm.internal.a):java.lang.Object");
    }
}
