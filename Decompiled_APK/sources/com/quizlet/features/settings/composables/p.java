package com.quizlet.features.settings.composables;

import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class p implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.settings.data.states.y b;
    public final /* synthetic */ n c;

    public p(com.quizlet.features.settings.data.states.y yVar, n nVar, int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = yVar;
                this.c = nVar;
                break;
            case 2:
                this.b = yVar;
                this.c = nVar;
                break;
            default:
                this.b = yVar;
                this.c = nVar;
                break;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0021  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0057  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x008c  */
    @Override // kotlin.jvm.functions.Function2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r9, java.lang.Object r10) {
        /*
            r8 = this;
            int r0 = r8.a
            switch(r0) {
                case 0: goto L71;
                case 1: goto L3b;
                default: goto L5;
            }
        L5:
            r5 = r9
            androidx.compose.runtime.l r5 = (androidx.compose.runtime.InterfaceC0806l) r5
            java.lang.Number r10 = (java.lang.Number) r10
            int r9 = r10.intValue()
            r9 = r9 & 3
            r10 = 2
            if (r9 != r10) goto L21
            r9 = r5
            androidx.compose.runtime.p r9 = (androidx.compose.runtime.C0814p) r9
            boolean r10 = r9.x()
            if (r10 != 0) goto L1d
            goto L21
        L1d:
            r9.Q()
            goto L38
        L21:
            androidx.compose.ui.n r9 = androidx.compose.ui.n.b
            java.lang.String r10 = "sound_effects_switch"
            androidx.compose.ui.q r2 = androidx.compose.ui.platform.N.G(r9, r10)
            com.quizlet.features.settings.data.states.y r9 = r8.b
            boolean r1 = r9.j
            com.quizlet.features.settings.composables.n r9 = r8.c
            kotlin.jvm.functions.Function1 r3 = r9.b
            r4 = 0
            r6 = 0
            r7 = 8
            com.google.android.gms.internal.mlkit_vision_document_scanner.S4.a(r1, r2, r3, r4, r5, r6, r7)
        L38:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L3b:
            r4 = r9
            androidx.compose.runtime.l r4 = (androidx.compose.runtime.InterfaceC0806l) r4
            java.lang.Number r10 = (java.lang.Number) r10
            int r9 = r10.intValue()
            r9 = r9 & 3
            r10 = 2
            if (r9 != r10) goto L57
            r9 = r4
            androidx.compose.runtime.p r9 = (androidx.compose.runtime.C0814p) r9
            boolean r10 = r9.x()
            if (r10 != 0) goto L53
            goto L57
        L53:
            r9.Q()
            goto L6e
        L57:
            androidx.compose.ui.n r9 = androidx.compose.ui.n.b
            java.lang.String r10 = "push_notification_switch"
            androidx.compose.ui.q r1 = androidx.compose.ui.platform.N.G(r9, r10)
            com.quizlet.features.settings.data.states.y r9 = r8.b
            boolean r0 = r9.i
            com.quizlet.features.settings.composables.n r9 = r8.c
            kotlin.jvm.functions.Function1 r2 = r9.a
            r3 = 0
            r5 = 0
            r6 = 8
            com.google.android.gms.internal.mlkit_vision_document_scanner.S4.a(r0, r1, r2, r3, r4, r5, r6)
        L6e:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L71:
            androidx.compose.runtime.l r9 = (androidx.compose.runtime.InterfaceC0806l) r9
            java.lang.Number r10 = (java.lang.Number) r10
            int r10 = r10.intValue()
            r10 = r10 & 3
            r0 = 2
            if (r10 != r0) goto L8c
            r10 = r9
            androidx.compose.runtime.p r10 = (androidx.compose.runtime.C0814p) r10
            boolean r0 = r10.x()
            if (r0 != 0) goto L88
            goto L8c
        L88:
            r10.Q()
            goto La5
        L8c:
            com.quizlet.features.settings.data.states.y r10 = r8.b
            com.quizlet.features.settings.composables.n r0 = r8.c
            r1 = 0
            r2 = 0
            com.google.android.gms.internal.mlkit_vision_common.I2.d(r10, r0, r1, r9, r2)
            com.google.android.gms.internal.mlkit_vision_common.F2.a(r1, r9, r2)
            com.google.android.gms.internal.mlkit_vision_common.I2.e(r10, r0, r1, r9, r2)
            boolean r10 = r10.m
            if (r10 == 0) goto La5
            com.google.android.gms.internal.mlkit_vision_common.F2.a(r1, r9, r2)
            com.google.android.gms.internal.mlkit_vision_common.I2.a(r0, r9, r2)
        La5:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.settings.composables.p.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
