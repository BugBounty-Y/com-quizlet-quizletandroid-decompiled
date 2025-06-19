package androidx.compose.foundation;

import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class C extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlin.jvm.internal.F b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(com.google.android.gms.internal.instantapps.a aVar, androidx.compose.ui.draganddrop.e eVar, kotlin.jvm.internal.F f) {
        super(1);
        this.a = 2;
        this.b = f;
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x0057  */
    @Override // kotlin.jvm.functions.Function1
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r4) {
        /*
            r3 = this;
            int r0 = r3.a
            switch(r0) {
                case 0: goto L40;
                case 1: goto L28;
                case 2: goto L16;
                default: goto L5;
            }
        L5:
            androidx.compose.ui.input.pointer.h r4 = (androidx.compose.ui.input.pointer.h) r4
            boolean r4 = r4.o
            if (r4 == 0) goto L13
            kotlin.jvm.internal.F r4 = r3.b
            r0 = 0
            r4.a = r0
            androidx.compose.ui.node.p0 r4 = androidx.compose.ui.node.p0.c
            goto L15
        L13:
            androidx.compose.ui.node.p0 r4 = androidx.compose.ui.node.p0.a
        L15:
            return r4
        L16:
            androidx.compose.ui.draganddrop.e r4 = (androidx.compose.ui.draganddrop.e) r4
            boolean r4 = r4.m
            if (r4 != 0) goto L1f
            androidx.compose.ui.node.p0 r4 = androidx.compose.ui.node.p0.b
            goto L27
        L1f:
            kotlin.jvm.internal.F r4 = r3.b
            boolean r0 = r4.a
            r4.a = r0
            androidx.compose.ui.node.p0 r4 = androidx.compose.ui.node.p0.a
        L27:
            return r4
        L28:
            androidx.compose.foundation.text.selection.o r4 = (androidx.compose.foundation.text.selection.C0534o) r4
            androidx.compose.ui.text.H r4 = r4.f
            androidx.compose.ui.text.G r4 = r4.a
            androidx.compose.ui.text.g r4 = r4.a
            java.lang.String r4 = r4.a
            int r4 = r4.length()
            if (r4 <= 0) goto L3d
            kotlin.jvm.internal.F r4 = r3.b
            r0 = 0
            r4.a = r0
        L3d:
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        L40:
            androidx.compose.ui.node.q0 r4 = (androidx.compose.ui.node.q0) r4
            kotlin.jvm.internal.F r0 = r3.b
            boolean r1 = r0.a
            r2 = 1
            if (r1 != 0) goto L57
            java.lang.String r1 = "null cannot be cast to non-null type androidx.compose.foundation.gestures.ScrollableContainerNode"
            kotlin.jvm.internal.Intrinsics.e(r4, r1)
            androidx.compose.foundation.gestures.l0 r4 = (androidx.compose.foundation.gestures.C0336l0) r4
            boolean r4 = r4.n
            if (r4 == 0) goto L55
            goto L57
        L55:
            r4 = 0
            goto L58
        L57:
            r4 = r2
        L58:
            r0.a = r4
            r4 = r4 ^ r2
            java.lang.Boolean r4 = java.lang.Boolean.valueOf(r4)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.C.invoke(java.lang.Object):java.lang.Object");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C(kotlin.jvm.internal.F f, int i) {
        super(1);
        this.a = i;
        this.b = f;
    }
}
