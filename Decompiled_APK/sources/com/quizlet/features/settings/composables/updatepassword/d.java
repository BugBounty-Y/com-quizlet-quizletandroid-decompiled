package com.quizlet.features.settings.composables.updatepassword;

import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class d implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.settings.data.models.h b;
    public final /* synthetic */ com.quizlet.features.settings.data.states.h c;
    public final /* synthetic */ String d;
    public final /* synthetic */ Function1 e;
    public final /* synthetic */ String f;
    public final /* synthetic */ Function1 g;
    public final /* synthetic */ String h;
    public final /* synthetic */ Function1 i;

    public /* synthetic */ d(com.quizlet.features.settings.data.models.h hVar, com.quizlet.features.settings.data.states.h hVar2, String str, Function1 function1, String str2, Function1 function12, String str3, Function1 function13, int i) {
        this.a = i;
        this.b = hVar;
        this.c = hVar2;
        this.d = str;
        this.e = function1;
        this.f = str2;
        this.g = function12;
        this.h = str3;
        this.i = function13;
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x003a  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x008c  */
    @Override // kotlin.jvm.functions.c
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r13, java.lang.Object r14, java.lang.Object r15) {
        /*
            r12 = this;
            int r0 = r12.a
            switch(r0) {
                case 0: goto L68;
                default: goto L5;
            }
        L5:
            androidx.compose.foundation.layout.z0 r13 = (androidx.compose.foundation.layout.z0) r13
            r10 = r14
            androidx.compose.runtime.l r10 = (androidx.compose.runtime.InterfaceC0806l) r10
            java.lang.Number r15 = (java.lang.Number) r15
            int r14 = r15.intValue()
            java.lang.String r15 = "innerPadding"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r13, r15)
            r15 = r14 & 6
            if (r15 != 0) goto L26
            r15 = r10
            androidx.compose.runtime.p r15 = (androidx.compose.runtime.C0814p) r15
            boolean r15 = r15.f(r13)
            if (r15 == 0) goto L24
            r15 = 4
            goto L25
        L24:
            r15 = 2
        L25:
            r14 = r14 | r15
        L26:
            r14 = r14 & 19
            r15 = 18
            if (r14 != r15) goto L3a
            r14 = r10
            androidx.compose.runtime.p r14 = (androidx.compose.runtime.C0814p) r14
            boolean r15 = r14.x()
            if (r15 != 0) goto L36
            goto L3a
        L36:
            r14.Q()
            goto L65
        L3a:
            androidx.compose.ui.n r14 = androidx.compose.ui.n.b
            androidx.compose.ui.q r13 = androidx.compose.foundation.layout.AbstractC0382e.t(r14, r13)
            com.quizlet.themes.m r14 = com.quizlet.themes.m.g
            r14.q()
            float r15 = com.quizlet.ui.resources.designsystem.generated.j.i
            r14.p()
            float r14 = com.quizlet.ui.resources.designsystem.generated.j.j
            androidx.compose.ui.q r1 = androidx.compose.foundation.layout.AbstractC0382e.v(r13, r15, r14)
            com.quizlet.features.settings.data.models.h r0 = r12.b
            java.lang.String r7 = r12.h
            r11 = 0
            com.quizlet.features.settings.data.states.h r2 = r12.c
            java.lang.String r3 = r12.d
            kotlin.jvm.functions.Function1 r4 = r12.e
            java.lang.String r5 = r12.f
            kotlin.jvm.functions.Function1 r6 = r12.g
            kotlin.jvm.functions.Function1 r8 = r12.i
            r9 = 0
            com.google.android.gms.internal.mlkit_vision_common.AbstractC3495m3.a(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11)
        L65:
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        L68:
            androidx.compose.foundation.layout.C r13 = (androidx.compose.foundation.layout.C) r13
            r10 = r14
            androidx.compose.runtime.l r10 = (androidx.compose.runtime.InterfaceC0806l) r10
            java.lang.Number r15 = (java.lang.Number) r15
            int r14 = r15.intValue()
            java.lang.String r15 = "$this$TitleMessageButtonsModalContent"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r13, r15)
            r13 = r14 & 17
            r14 = 16
            if (r13 != r14) goto L8c
            r13 = r10
            androidx.compose.runtime.p r13 = (androidx.compose.runtime.C0814p) r13
            boolean r14 = r13.x()
            if (r14 != 0) goto L88
            goto L8c
        L88:
            r13.Q()
            goto Lb3
        L8c:
            androidx.compose.ui.n r0 = androidx.compose.ui.n.b
            com.quizlet.themes.m r13 = com.quizlet.themes.m.g
            r13.s()
            float r2 = com.quizlet.ui.resources.designsystem.generated.j.h
            r1 = 0
            r5 = 13
            r3 = 0
            r4 = 0
            androidx.compose.ui.q r1 = androidx.compose.foundation.layout.AbstractC0382e.y(r0, r1, r2, r3, r4, r5)
            com.quizlet.features.settings.data.models.h r0 = r12.b
            java.lang.String r7 = r12.h
            r11 = 0
            com.quizlet.features.settings.data.states.h r2 = r12.c
            java.lang.String r3 = r12.d
            kotlin.jvm.functions.Function1 r4 = r12.e
            java.lang.String r5 = r12.f
            kotlin.jvm.functions.Function1 r6 = r12.g
            kotlin.jvm.functions.Function1 r8 = r12.i
            r9 = 0
            com.google.android.gms.internal.mlkit_vision_common.AbstractC3495m3.a(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11)
        Lb3:
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.settings.composables.updatepassword.d.invoke(java.lang.Object, java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
