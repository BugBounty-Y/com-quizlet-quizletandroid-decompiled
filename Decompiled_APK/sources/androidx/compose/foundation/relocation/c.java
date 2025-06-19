package androidx.compose.foundation.relocation;

/* loaded from: classes.dex */
public final class c {
    public final androidx.compose.runtime.collection.b a = new androidx.compose.runtime.collection.b(new e[16]);

    /* JADX WARN: Code restructure failed: missing block: B:21:0x005e, code lost:
    
        if (r8 < r2) goto L17;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:18:0x005a -> B:20:0x005d). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(androidx.compose.ui.geometry.c r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r7 = this;
            boolean r0 = r9 instanceof androidx.compose.foundation.relocation.b
            if (r0 == 0) goto L13
            r0 = r9
            androidx.compose.foundation.relocation.b r0 = (androidx.compose.foundation.relocation.b) r0
            int r1 = r0.p
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.p = r1
            goto L18
        L13:
            androidx.compose.foundation.relocation.b r0 = new androidx.compose.foundation.relocation.b
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.n
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.p
            r3 = 1
            if (r2 == 0) goto L38
            if (r2 != r3) goto L30
            int r8 = r0.m
            int r2 = r0.l
            java.lang.Object[] r4 = r0.k
            androidx.compose.ui.geometry.c r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r9 = r5
            goto L5d
        L30:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            androidx.compose.runtime.collection.b r9 = r7.a
            int r2 = r9.c
            if (r2 <= 0) goto L60
            java.lang.Object[] r9 = r9.a
            r4 = 0
            r6 = r9
            r9 = r8
            r8 = r4
            r4 = r6
        L48:
            r5 = r4[r8]
            androidx.compose.foundation.relocation.e r5 = (androidx.compose.foundation.relocation.e) r5
            r0.j = r9
            r0.k = r4
            r0.l = r2
            r0.m = r8
            r0.p = r3
            java.lang.Object r5 = androidx.compose.foundation.relocation.d.b(r5, r9, r0)
            if (r5 != r1) goto L5d
            return r1
        L5d:
            int r8 = r8 + r3
            if (r8 < r2) goto L48
        L60:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.relocation.c.a(androidx.compose.ui.geometry.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
