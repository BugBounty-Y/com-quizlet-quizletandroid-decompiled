package androidx.compose.ui.platform;

import androidx.core.view.C1038b;

/* renamed from: androidx.compose.ui.platform.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0954m extends C1038b {
    public final /* synthetic */ C0971v d;
    public final /* synthetic */ androidx.compose.ui.node.E e;
    public final /* synthetic */ C0971v f;

    public C0954m(C0971v c0971v, androidx.compose.ui.node.E e, C0971v c0971v2) {
        this.d = c0971v;
        this.e = e;
        this.f = c0971v2;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x004a  */
    @Override // androidx.core.view.C1038b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(android.view.View r8, androidx.core.view.accessibility.e r9) {
        /*
            r7 = this;
            android.view.View$AccessibilityDelegate r0 = r7.a
            android.view.accessibility.AccessibilityNodeInfo r1 = r9.a
            r0.onInitializeAccessibilityNodeInfo(r8, r1)
            androidx.compose.ui.platform.v r8 = r7.d
            androidx.compose.ui.platform.F r0 = r8.m
            boolean r2 = r0.x()
            if (r2 == 0) goto L15
            r2 = 0
            r1.setVisibleToUser(r2)
        L15:
            androidx.compose.ui.node.E r2 = r7.e
            androidx.compose.ui.node.E r3 = r2.s()
        L1b:
            r4 = 0
            if (r3 == 0) goto L2e
            r5 = 8
            androidx.compose.ui.node.V r6 = r3.w
            boolean r5 = r6.h(r5)
            if (r5 == 0) goto L29
            goto L2f
        L29:
            androidx.compose.ui.node.E r3 = r3.s()
            goto L1b
        L2e:
            r3 = r4
        L2f:
            if (r3 == 0) goto L37
            int r3 = r3.b
            java.lang.Integer r4 = java.lang.Integer.valueOf(r3)
        L37:
            r3 = -1
            if (r4 == 0) goto L4a
            androidx.compose.ui.semantics.p r5 = r8.getSemanticsOwner()
            androidx.compose.ui.semantics.o r5 = r5.a()
            int r6 = r4.intValue()
            int r5 = r5.g
            if (r6 != r5) goto L4e
        L4a:
            java.lang.Integer r4 = java.lang.Integer.valueOf(r3)
        L4e:
            int r4 = r4.intValue()
            androidx.compose.ui.platform.v r5 = r7.f
            r9.b = r4
            r1.setParent(r5, r4)
            int r9 = r2.b
            androidx.collection.t r2 = r0.C
            int r2 = r2.d(r9)
            if (r2 == r3) goto L79
            androidx.compose.ui.platform.f0 r4 = r8.getAndroidViewsHandler$ui_release()
            androidx.compose.ui.viewinterop.i r4 = androidx.compose.ui.platform.N.E(r4, r2)
            if (r4 == 0) goto L71
            r1.setTraversalBefore(r4)
            goto L74
        L71:
            r1.setTraversalBefore(r5, r2)
        L74:
            java.lang.String r2 = r0.E
            androidx.compose.ui.platform.C0971v.a(r8, r9, r1, r2)
        L79:
            androidx.collection.t r2 = r0.D
            int r2 = r2.d(r9)
            if (r2 == r3) goto L97
            androidx.compose.ui.platform.f0 r3 = r8.getAndroidViewsHandler$ui_release()
            androidx.compose.ui.viewinterop.i r3 = androidx.compose.ui.platform.N.E(r3, r2)
            if (r3 == 0) goto L8f
            r1.setTraversalAfter(r3)
            goto L92
        L8f:
            r1.setTraversalAfter(r5, r2)
        L92:
            java.lang.String r0 = r0.F
            androidx.compose.ui.platform.C0971v.a(r8, r9, r1, r0)
        L97:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.C0954m.d(android.view.View, androidx.core.view.accessibility.e):void");
    }
}
