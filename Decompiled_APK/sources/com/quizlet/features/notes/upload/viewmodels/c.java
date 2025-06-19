package com.quizlet.features.notes.upload.viewmodels;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import com.quizlet.data.model.FlashcardsInfo;
import com.quizlet.data.model.NotesToValueInfo;
import com.quizlet.data.model.m2;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.X;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public abstract class c extends com.quizlet.features.notes.common.viewmodels.b {
    public final m0 e;
    public final com.quizlet.features.notes.logging.f f;
    public final com.quizlet.data.repository.explanations.question.a g;
    public final com.quizlet.data.repository.explanations.question.a h;
    public final com.quizlet.data.repository.explanations.question.a i;
    public final com.google.firebase.crashlytics.internal.settings.b j;
    public final d0 k;
    public final m2 l;
    public int m;
    public int n;
    public int o;
    public final C4203d p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(m0 stateHandle, com.quizlet.features.notes.logging.f notesEventLogger, long j, com.quizlet.data.interactor.metering.b getMeteringInfo, com.quizlet.data.repository.explanations.question.a magicNotesCharacterMinimum, com.quizlet.data.repository.explanations.question.a magicNotesCharacterMaximum, com.quizlet.data.repository.explanations.question.a magicNotesFileMaximumSize, com.google.firebase.crashlytics.internal.settings.b addStudyMaterialToFolderUseCase) {
        super(j, notesEventLogger, getMeteringInfo);
        Intrinsics.checkNotNullParameter(stateHandle, "stateHandle");
        Intrinsics.checkNotNullParameter(notesEventLogger, "notesEventLogger");
        Intrinsics.checkNotNullParameter(getMeteringInfo, "getMeteringInfo");
        Intrinsics.checkNotNullParameter(magicNotesCharacterMinimum, "magicNotesCharacterMinimum");
        Intrinsics.checkNotNullParameter(magicNotesCharacterMaximum, "magicNotesCharacterMaximum");
        Intrinsics.checkNotNullParameter(magicNotesFileMaximumSize, "magicNotesFileMaximumSize");
        Intrinsics.checkNotNullParameter(addStudyMaterialToFolderUseCase, "addStudyMaterialToFolderUseCase");
        this.e = stateHandle;
        this.f = notesEventLogger;
        this.g = magicNotesCharacterMinimum;
        this.h = magicNotesCharacterMaximum;
        this.i = magicNotesFileMaximumSize;
        this.j = addStudyMaterialToFolderUseCase;
        this.k = e0.b(0, 1, null, 5);
        Object objA = stateHandle.a("source");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.l = (m2) objA;
        this.p = new C4203d(this);
        E.A(p0.j(this), null, null, new a(this, null), 3);
    }

    public final AddMaterialFolderData C() {
        return (AddMaterialFolderData) this.e.a("addMaterialFolderData");
    }

    public final boolean D() {
        Boolean bool = (Boolean) this.e.a("isPrivate");
        if (bool != null) {
            return bool.booleanValue();
        }
        return false;
    }

    public abstract X E();

    public final void F(NotesToValueInfo magicNotes, AddMaterialFolderData addMaterialFolderData) {
        Long l;
        Intrinsics.checkNotNullParameter(magicNotes, "magicNotes");
        m2 m2Var = m2.a;
        d0 d0Var = this.k;
        if (this.l == m2Var) {
            d0Var.h(new com.quizlet.features.notes.upload.events.c(magicNotes.a, false, addMaterialFolderData));
            return;
        }
        FlashcardsInfo flashcardsInfo = magicNotes.f;
        if (flashcardsInfo == null || (l = flashcardsInfo.c) == null) {
            d0Var.h(new com.quizlet.features.notes.upload.events.c(magicNotes.a, true, null));
        } else {
            d0Var.h(new com.quizlet.features.notes.upload.events.g(l.longValue(), addMaterialFolderData));
        }
    }

    public void G(String str) {
    }

    public void H() {
    }

    public void I() {
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object J(java.lang.String r10, kotlin.coroutines.jvm.internal.c r11) {
        /*
            r9 = this;
            boolean r0 = r11 instanceof com.quizlet.features.notes.upload.viewmodels.b
            if (r0 == 0) goto L13
            r0 = r11
            com.quizlet.features.notes.upload.viewmodels.b r0 = (com.quizlet.features.notes.upload.viewmodels.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.notes.upload.viewmodels.b r0 = new com.quizlet.features.notes.upload.viewmodels.b
            r0.<init>(r9, r11)
        L18:
            java.lang.Object r11 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            com.quizlet.features.infra.models.folders.AddMaterialFolderData r10 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r11)     // Catch: java.lang.Exception -> L69
            kotlin.r r11 = (kotlin.r) r11     // Catch: java.lang.Exception -> L69
            java.lang.Object r11 = r11.a     // Catch: java.lang.Exception -> L69
            goto L62
        L2d:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            com.quizlet.data.model.m2 r11 = com.quizlet.data.model.m2.b
            com.quizlet.data.model.m2 r2 = r9.l
            if (r2 != r11) goto L43
            com.quizlet.features.infra.models.folders.AddMaterialFolderData r10 = r9.C()
            return r10
        L43:
            com.quizlet.features.infra.models.folders.AddMaterialFolderData r11 = r9.C()
            if (r11 == 0) goto L79
            com.google.firebase.crashlytics.internal.settings.b r2 = r9.j     // Catch: java.lang.Exception -> L68
            com.quizlet.data.model.g0 r4 = new com.quizlet.data.model.g0     // Catch: java.lang.Exception -> L68
            long r5 = r11.a     // Catch: java.lang.Exception -> L68
            com.quizlet.generated.enums.y1 r7 = com.quizlet.generated.enums.y1.NOTE     // Catch: java.lang.Exception -> L68
            r4.<init>(r5, r10, r7)     // Catch: java.lang.Exception -> L68
            r0.j = r11     // Catch: java.lang.Exception -> L68
            r0.m = r3     // Catch: java.lang.Exception -> L68
            java.lang.Object r10 = r2.a(r4, r0)     // Catch: java.lang.Exception -> L68
            if (r10 != r1) goto L5f
            return r1
        L5f:
            r8 = r11
            r11 = r10
            r10 = r8
        L62:
            kotlin.p r0 = kotlin.r.b     // Catch: java.lang.Exception -> L69
            boolean r11 = r11 instanceof kotlin.q     // Catch: java.lang.Exception -> L69
            r11 = r11 ^ r3
            goto L6a
        L68:
            r10 = r11
        L69:
            r11 = 0
        L6a:
            long r0 = r10.a
            java.lang.String r2 = "folderName"
            java.lang.String r10 = r10.b
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r2)
            com.quizlet.features.infra.models.folders.AddMaterialFolderData r2 = new com.quizlet.features.infra.models.folders.AddMaterialFolderData
            r2.<init>(r10, r0, r11)
            return r2
        L79:
            r10 = 0
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.upload.viewmodels.c.J(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
