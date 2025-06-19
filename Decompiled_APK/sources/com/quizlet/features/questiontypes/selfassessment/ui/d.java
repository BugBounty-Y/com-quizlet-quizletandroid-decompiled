package com.quizlet.features.questiontypes.selfassessment.ui;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class d implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ int b;
    public final /* synthetic */ com.quizlet.features.infra.models.flashcards.f c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ Function1 e;

    public d(int i, com.quizlet.features.infra.models.flashcards.f fVar, Function0 function0, Function1 function1) {
        this.b = i;
        this.c = fVar;
        this.d = function0;
        this.e = function1;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0021  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0050  */
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
                case 0: goto L34;
                default: goto L5;
            }
        L5:
            r6 = r9
            androidx.compose.runtime.l r6 = (androidx.compose.runtime.InterfaceC0806l) r6
            java.lang.Number r10 = (java.lang.Number) r10
            int r9 = r10.intValue()
            r9 = r9 & 3
            r10 = 2
            if (r9 != r10) goto L21
            r9 = r6
            androidx.compose.runtime.p r9 = (androidx.compose.runtime.C0814p) r9
            boolean r10 = r9.x()
            if (r10 != 0) goto L1d
            goto L21
        L1d:
            r9.Q()
            goto L31
        L21:
            com.quizlet.features.infra.models.flashcards.f r9 = r8.c
            kotlin.jvm.functions.Function1 r4 = r8.e
            com.quizlet.features.notes.detail.composables.magicnotesdetail.G r5 = r9.c
            int r1 = r8.b
            com.google.android.gms.internal.mlkit_vision_barcode.D6 r2 = r9.b
            kotlin.jvm.functions.Function0 r3 = r8.d
            r7 = 0
            com.google.android.gms.internal.mlkit_vision_camera.m3.a(r1, r2, r3, r4, r5, r6, r7)
        L31:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L34:
            r5 = r9
            androidx.compose.runtime.l r5 = (androidx.compose.runtime.InterfaceC0806l) r5
            java.lang.Number r10 = (java.lang.Number) r10
            int r9 = r10.intValue()
            r9 = r9 & 3
            r10 = 2
            if (r9 != r10) goto L50
            r9 = r5
            androidx.compose.runtime.p r9 = (androidx.compose.runtime.C0814p) r9
            boolean r10 = r9.x()
            if (r10 != 0) goto L4c
            goto L50
        L4c:
            r9.Q()
            goto L60
        L50:
            com.quizlet.features.infra.models.flashcards.f r9 = r8.c
            kotlin.jvm.functions.Function1 r3 = r8.e
            com.quizlet.features.notes.detail.composables.magicnotesdetail.G r4 = r9.c
            int r0 = r8.b
            com.google.android.gms.internal.mlkit_vision_barcode.D6 r1 = r9.b
            kotlin.jvm.functions.Function0 r2 = r8.d
            r6 = 0
            com.google.android.gms.internal.mlkit_vision_camera.m3.a(r0, r1, r2, r3, r4, r5, r6)
        L60:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questiontypes.selfassessment.ui.d.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }

    public d(com.quizlet.features.infra.models.flashcards.f fVar, int i, Function0 function0, Function1 function1) {
        this.c = fVar;
        this.b = i;
        this.d = function0;
        this.e = function1;
    }
}
