package com.quizlet.features.flashcards;

import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.flashcards.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4229c implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ FlashcardsActivity b;

    public /* synthetic */ C4229c(FlashcardsActivity flashcardsActivity, int i) {
        this.a = i;
        this.b = flashcardsActivity;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0021  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0058  */
    @Override // kotlin.jvm.functions.Function2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r13, java.lang.Object r14) {
        /*
            r12 = this;
            int r0 = r12.a
            switch(r0) {
                case 0: goto L3c;
                default: goto L5;
            }
        L5:
            r5 = r13
            androidx.compose.runtime.l r5 = (androidx.compose.runtime.InterfaceC0806l) r5
            java.lang.Number r14 = (java.lang.Number) r14
            int r13 = r14.intValue()
            r13 = r13 & 3
            r14 = 2
            if (r13 != r14) goto L21
            r13 = r5
            androidx.compose.runtime.p r13 = (androidx.compose.runtime.C0814p) r13
            boolean r14 = r13.x()
            if (r14 != 0) goto L1d
            goto L21
        L1d:
            r13.Q()
            goto L39
        L21:
            com.quizlet.features.flashcards.c r13 = new com.quizlet.features.flashcards.c
            com.quizlet.features.flashcards.FlashcardsActivity r14 = r12.b
            r0 = 0
            r13.<init>(r14, r0)
            r14 = 269939413(0x1016f2d5, float:2.9769355E-29)
            androidx.compose.runtime.internal.d r4 = androidx.compose.runtime.internal.e.e(r14, r13, r5)
            r6 = 3072(0xc00, float:4.305E-42)
            r7 = 7
            r1 = 0
            r2 = 0
            r3 = 0
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5.b(r1, r2, r3, r4, r5, r6, r7)
        L39:
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        L3c:
            r10 = r13
            androidx.compose.runtime.l r10 = (androidx.compose.runtime.InterfaceC0806l) r10
            java.lang.Number r14 = (java.lang.Number) r14
            int r13 = r14.intValue()
            r13 = r13 & 3
            r14 = 2
            if (r13 != r14) goto L58
            r13 = r10
            androidx.compose.runtime.p r13 = (androidx.compose.runtime.C0814p) r13
            boolean r14 = r13.x()
            if (r14 != 0) goto L54
            goto L58
        L54:
            r13.Q()
            goto Lb6
        L58:
            com.quizlet.features.flashcards.FlashcardsActivity r13 = r12.b
            android.content.Intent r14 = r13.getIntent()
            java.lang.String r0 = "navigationSource"
            r1 = 0
            int r0 = r14.getIntExtra(r0, r1)
            android.content.Intent r14 = r13.getIntent()
            java.lang.String r2 = "studyableModelData"
            android.os.Parcelable r14 = r14.getParcelableExtra(r2)
            if (r14 == 0) goto Lb9
            com.quizlet.features.infra.models.studymodeshared.StudyableModelData r14 = (com.quizlet.features.infra.models.studymodeshared.StudyableModelData) r14
            android.content.Intent r2 = r13.getIntent()
            java.lang.String r3 = "studyableModelLocalId"
            r4 = 0
            long r2 = r2.getLongExtra(r3, r4)
            android.content.Intent r4 = r13.getIntent()
            java.lang.String r5 = "studyableModelTitle"
            java.lang.String r4 = r4.getStringExtra(r5)
            java.lang.String r5 = ""
            if (r4 != 0) goto L8e
            r4 = r5
        L8e:
            android.content.Intent r6 = r13.getIntent()
            java.lang.String r7 = "selectedOnlyIntent"
            boolean r1 = r6.getBooleanExtra(r7, r1)
            android.content.Intent r6 = r13.getIntent()
            java.lang.String r7 = "screen_name_key"
            java.lang.String r6 = r6.getStringExtra(r7)
            if (r6 != 0) goto La5
            r6 = r5
        La5:
            com.quizlet.data.repository.folderwithcreatorinclass.e r13 = r13.i
            java.lang.Object r13 = r13.getValue()
            r9 = r13
            com.quizlet.features.flashcards.S r9 = (com.quizlet.features.flashcards.S) r9
            r8 = 0
            r11 = 0
            r7 = 0
            r5 = r1
            r1 = r14
            com.quizlet.features.flashcards.navigation.d.a(r0, r1, r2, r4, r5, r6, r7, r8, r9, r10, r11)
        Lb6:
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        Lb9:
            java.lang.IllegalArgumentException r13 = new java.lang.IllegalArgumentException
            java.lang.String r14 = "Required value was null."
            r13.<init>(r14)
            throw r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.C4229c.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
