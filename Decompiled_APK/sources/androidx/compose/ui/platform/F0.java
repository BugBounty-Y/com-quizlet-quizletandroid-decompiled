package androidx.compose.ui.platform;

/* loaded from: classes.dex */
public abstract class F0 {
    public static final androidx.compose.runtime.X0 a = new androidx.compose.runtime.X0(O.D);

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(androidx.compose.foundation.text.input.internal.w r4, androidx.compose.foundation.text.input.internal.C0500f r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            boolean r0 = r6 instanceof androidx.compose.ui.platform.D0
            if (r0 == 0) goto L13
            r0 = r6
            androidx.compose.ui.platform.D0 r0 = (androidx.compose.ui.platform.D0) r0
            int r1 = r0.k
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.k = r1
            goto L18
        L13:
            androidx.compose.ui.platform.D0 r0 = new androidx.compose.ui.platform.D0
            r0.<init>(r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r1 = r0.k
            r2 = 1
            if (r1 == 0) goto L34
            if (r1 == r2) goto L2b
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L2b:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.KotlinNothingValueException r4 = new kotlin.KotlinNothingValueException
            r4.<init>()
            throw r4
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r6 = r4
            androidx.compose.ui.p r6 = (androidx.compose.ui.p) r6
            androidx.compose.ui.p r6 = r6.a
            boolean r6 = r6.m
            if (r6 == 0) goto L63
            androidx.compose.ui.node.g0 r6 = androidx.compose.ui.node.AbstractC0910f.w(r4)
            androidx.compose.ui.node.E r4 = androidx.compose.ui.node.AbstractC0910f.v(r4)
            androidx.compose.runtime.y r4 = r4.u
            androidx.compose.runtime.internal.i r4 = (androidx.compose.runtime.internal.i) r4
            r4.getClass()
            androidx.compose.runtime.X0 r1 = androidx.compose.ui.platform.F0.a
            java.lang.Object r4 = androidx.compose.runtime.C0776c.B(r4, r1)
            if (r4 != 0) goto L5d
            r0.k = r2
            b(r6, r5, r0)
            return
        L5d:
            java.lang.ClassCastException r4 = new java.lang.ClassCastException
            r4.<init>()
            throw r4
        L63:
            java.lang.IllegalArgumentException r4 = new java.lang.IllegalArgumentException
            java.lang.String r5 = "establishTextInputSession called from an unattached node"
            r4.<init>(r5)
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.F0.a(androidx.compose.foundation.text.input.internal.w, androidx.compose.foundation.text.input.internal.f, kotlin.coroutines.jvm.internal.c):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(androidx.compose.ui.node.g0 r4, androidx.compose.foundation.text.input.internal.C0500f r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            boolean r0 = r6 instanceof androidx.compose.ui.platform.E0
            if (r0 == 0) goto L13
            r0 = r6
            androidx.compose.ui.platform.E0 r0 = (androidx.compose.ui.platform.E0) r0
            int r1 = r0.k
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.k = r1
            goto L18
        L13:
            androidx.compose.ui.platform.E0 r0 = new androidx.compose.ui.platform.E0
            r0.<init>(r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r1 = r0.k
            r2 = 1
            if (r1 == 0) goto L40
            if (r1 == r2) goto L37
            r4 = 2
            if (r1 == r4) goto L2e
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L2e:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.KotlinNothingValueException r4 = new kotlin.KotlinNothingValueException
            r4.<init>()
            throw r4
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.KotlinNothingValueException r4 = new kotlin.KotlinNothingValueException
            r4.<init>()
            throw r4
        L40:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.k = r2
            androidx.compose.ui.platform.v r4 = (androidx.compose.ui.platform.C0971v) r4
            r4.F(r5, r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.F0.b(androidx.compose.ui.node.g0, androidx.compose.foundation.text.input.internal.f, kotlin.coroutines.jvm.internal.c):void");
    }
}
