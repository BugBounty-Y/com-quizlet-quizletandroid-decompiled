package androidx.compose.ui.platform;

import android.view.ViewGroup;

/* loaded from: classes.dex */
public abstract class v1 {
    public static final ViewGroup.LayoutParams a = new ViewGroup.LayoutParams(-2, -2);

    /* JADX WARN: Removed duplicated region for block: B:20:0x005a  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0092  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00af  */
    /* JADX WARN: Type inference failed for: r4v3, types: [java.lang.Object, java.util.Collection] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.ui.platform.t1 a(androidx.compose.ui.platform.AbstractC0930a r6, androidx.compose.runtime.AbstractC0827t r7, androidx.compose.runtime.internal.d r8) {
        /*
            java.util.concurrent.atomic.AtomicBoolean r0 = androidx.compose.ui.platform.AbstractC0968t0.a
            r1 = 0
            r2 = 1
            boolean r0 = r0.compareAndSet(r1, r2)
            r3 = 0
            if (r0 == 0) goto L41
            r0 = 6
            kotlinx.coroutines.channels.h r0 = com.google.android.gms.internal.mlkit_vision_camera.D1.a(r2, r0, r3)
            kotlin.u r2 = androidx.compose.ui.platform.Z.l
            java.lang.Object r2 = r2.getValue()
            kotlin.coroutines.CoroutineContext r2 = (kotlin.coroutines.CoroutineContext) r2
            kotlinx.coroutines.internal.d r2 = kotlinx.coroutines.E.c(r2)
            androidx.compose.ui.platform.s0 r4 = new androidx.compose.ui.platform.s0
            r4.<init>(r0, r3)
            r5 = 3
            kotlinx.coroutines.E.A(r2, r3, r3, r4, r5)
            androidx.compose.runtime.b0 r2 = new androidx.compose.runtime.b0
            r4 = 19
            r2.<init>(r0, r4)
            java.lang.Object r0 = androidx.compose.runtime.snapshots.m.b
            monitor-enter(r0)
            java.lang.Object r4 = androidx.compose.runtime.snapshots.m.h     // Catch: java.lang.Throwable -> L3e
            java.util.ArrayList r2 = kotlin.collections.CollectionsKt.d0(r4, r2)     // Catch: java.lang.Throwable -> L3e
            androidx.compose.runtime.snapshots.m.h = r2     // Catch: java.lang.Throwable -> L3e
            kotlin.Unit r2 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L3e
            monitor-exit(r0)
            androidx.compose.runtime.snapshots.m.a()
            goto L41
        L3e:
            r6 = move-exception
            monitor-exit(r0)
            throw r6
        L41:
            int r0 = r6.getChildCount()
            if (r0 <= 0) goto L54
            android.view.View r0 = r6.getChildAt(r1)
            boolean r1 = r0 instanceof androidx.compose.ui.platform.C0971v
            if (r1 == 0) goto L52
            androidx.compose.ui.platform.v r0 = (androidx.compose.ui.platform.C0971v) r0
            goto L58
        L52:
            r0 = r3
            goto L58
        L54:
            r6.removeAllViews()
            goto L52
        L58:
            if (r0 != 0) goto L70
            androidx.compose.ui.platform.v r0 = new androidx.compose.ui.platform.v
            android.content.Context r1 = r6.getContext()
            kotlin.coroutines.CoroutineContext r2 = r7.i()
            r0.<init>(r1, r2)
            android.view.View r1 = r0.getView()
            android.view.ViewGroup$LayoutParams r2 = androidx.compose.ui.platform.v1.a
            r6.addView(r1, r2)
        L70:
            androidx.compose.ui.node.s0 r6 = new androidx.compose.ui.node.s0
            androidx.compose.ui.node.E r1 = r0.getRoot()
            r6.<init>(r1)
            androidx.compose.runtime.w r1 = new androidx.compose.runtime.w
            r1.<init>(r7, r6)
            android.view.View r6 = r0.getView()
            r2 = 2131429921(0x7f0b0a21, float:1.8481528E38)
            java.lang.Object r6 = r6.getTag(r2)
            boolean r4 = r6 instanceof androidx.compose.ui.platform.t1
            if (r4 == 0) goto L90
            r3 = r6
            androidx.compose.ui.platform.t1 r3 = (androidx.compose.ui.platform.t1) r3
        L90:
            if (r3 != 0) goto L9e
            androidx.compose.ui.platform.t1 r3 = new androidx.compose.ui.platform.t1
            r3.<init>(r0, r1)
            android.view.View r6 = r0.getView()
            r6.setTag(r2, r3)
        L9e:
            r3.a(r8)
            kotlin.coroutines.CoroutineContext r6 = r0.getCoroutineContext()
            kotlin.coroutines.CoroutineContext r8 = r7.i()
            boolean r6 = kotlin.jvm.internal.Intrinsics.b(r6, r8)
            if (r6 != 0) goto Lb6
            kotlin.coroutines.CoroutineContext r6 = r7.i()
            r0.setCoroutineContext(r6)
        Lb6:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.v1.a(androidx.compose.ui.platform.a, androidx.compose.runtime.t, androidx.compose.runtime.internal.d):androidx.compose.ui.platform.t1");
    }
}
