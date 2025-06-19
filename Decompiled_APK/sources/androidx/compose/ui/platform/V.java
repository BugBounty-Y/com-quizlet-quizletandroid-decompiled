package androidx.compose.ui.platform;

import android.view.View;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.coroutines.CoroutineContext;

/* loaded from: classes.dex */
public final class V implements kotlinx.coroutines.C {
    public final View a;
    public final androidx.compose.ui.text.input.B b;
    public final kotlinx.coroutines.C c;
    public final AtomicReference d = new AtomicReference(null);

    public V(View view, androidx.compose.ui.text.input.B b, kotlinx.coroutines.C c) {
        this.a = view;
        this.b = b;
        this.c = c;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(androidx.compose.foundation.text.input.internal.B r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof androidx.compose.ui.platform.T
            if (r0 == 0) goto L13
            r0 = r7
            androidx.compose.ui.platform.T r0 = (androidx.compose.ui.platform.T) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            androidx.compose.ui.platform.T r0 = new androidx.compose.ui.platform.T
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 == r3) goto L2b
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L2b:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4f
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.util.concurrent.atomic.AtomicReference r7 = r5.d
            androidx.compose.foundation.text.selection.n0 r2 = new androidx.compose.foundation.text.selection.n0
            r4 = 21
            r2.<init>(r4, r6, r5)
            androidx.compose.ui.platform.U r6 = new androidx.compose.ui.platform.U
            r4 = 0
            r6.<init>(r5, r4)
            r0.l = r3
            androidx.compose.ui.t r3 = new androidx.compose.ui.t
            r3.<init>(r2, r7, r6, r4)
            java.lang.Object r6 = kotlinx.coroutines.E.m(r3, r0)
            if (r6 != r1) goto L4f
            return
        L4f:
            kotlin.KotlinNothingValueException r6 = new kotlin.KotlinNothingValueException
            r6.<init>()
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.V.a(androidx.compose.foundation.text.input.internal.B, kotlin.coroutines.jvm.internal.c):void");
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.c.getCoroutineContext();
    }
}
