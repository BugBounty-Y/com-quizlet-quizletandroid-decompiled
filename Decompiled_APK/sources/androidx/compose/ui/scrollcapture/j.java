package androidx.compose.ui.scrollcapture;

import androidx.compose.ui.text.android.x;

/* loaded from: classes.dex */
public final class j {
    public int a;
    public float b;
    public final Object c;

    public j(int i, e eVar) {
        this.a = i;
        this.c = eVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x001d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public float a(int r6, boolean r7, boolean r8, boolean r9) {
        /*
            r5 = this;
            r0 = 1
            r1 = 0
            java.lang.Object r2 = r5.c
            androidx.compose.ui.text.android.x r2 = (androidx.compose.ui.text.android.x) r2
            if (r7 == 0) goto L1d
            android.text.Layout r3 = r2.e
            int r3 = androidx.compose.ui.text.android.s.c(r3, r6, r7)
            android.text.Layout r4 = r2.e
            int r4 = r4.getLineStart(r3)
            int r3 = r2.f(r3)
            if (r6 == r4) goto L1f
            if (r6 != r3) goto L1d
            goto L1f
        L1d:
            r3 = r1
            goto L20
        L1f:
            r3 = r0
        L20:
            int r4 = r6 * 4
            if (r9 == 0) goto L28
            if (r3 == 0) goto L2d
            r0 = r1
            goto L2d
        L28:
            if (r3 == 0) goto L2c
            r0 = 2
            goto L2d
        L2c:
            r0 = 3
        L2d:
            int r4 = r4 + r0
            int r0 = r5.a
            if (r0 != r4) goto L35
            float r6 = r5.b
            return r6
        L35:
            if (r9 == 0) goto L3c
            float r6 = r2.h(r6, r7)
            goto L40
        L3c:
            float r6 = r2.i(r6, r7)
        L40:
            if (r8 == 0) goto L46
            r5.a = r4
            r5.b = r6
        L46:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.scrollcapture.j.a(int, boolean, boolean, boolean):float");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(float r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof androidx.compose.ui.scrollcapture.i
            if (r0 == 0) goto L13
            r0 = r6
            androidx.compose.ui.scrollcapture.i r0 = (androidx.compose.ui.scrollcapture.i) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.compose.ui.scrollcapture.i r0 = new androidx.compose.ui.scrollcapture.i
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.compose.ui.scrollcapture.j r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L49
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Float r6 = new java.lang.Float
            r6.<init>(r5)
            r0.j = r4
            r0.m = r3
            java.lang.Object r5 = r4.c
            androidx.compose.ui.scrollcapture.e r5 = (androidx.compose.ui.scrollcapture.e) r5
            java.lang.Object r6 = r5.invoke(r6, r0)
            if (r6 != r1) goto L48
            return r1
        L48:
            r5 = r4
        L49:
            java.lang.Number r6 = (java.lang.Number) r6
            float r6 = r6.floatValue()
            float r0 = r5.b
            float r0 = r0 + r6
            r5.b = r0
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.scrollcapture.j.b(float, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public j(x xVar) {
        this.c = xVar;
        this.a = -1;
    }
}
