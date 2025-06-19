package com.quizlet.features.notes.upload.viewmodels;

import androidx.lifecycle.m0;
import com.quizlet.generated.enums.EnumC4489i0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.X;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class e extends c {
    public final com.quizlet.features.notes.logging.f q;
    public final com.quizlet.data.interactor.notes.b r;
    public final String s;
    public final s0 t;
    public final EnumC4489i0 u;
    public final com.quizlet.features.notes.data.d v;
    public boolean w;
    public boolean x;
    public String y;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(m0 stateHandle, com.quizlet.features.notes.logging.f notesEventLogger, long j, com.quizlet.data.interactor.metering.b getMeteringInfo, com.quizlet.data.interactor.notes.b createNotesToValueInfoUseCase, com.quizlet.data.repository.explanations.question.a magicNotesCharacterMinimum, com.quizlet.data.repository.explanations.question.a magicNotesCharacterMaximum, com.quizlet.data.repository.explanations.question.a magicNotesFileMaximumSize, com.google.firebase.crashlytics.internal.settings.b addStudyMaterialToFolderUseCase) {
        s0 s0Var;
        Object value;
        super(stateHandle, notesEventLogger, j, getMeteringInfo, magicNotesCharacterMinimum, magicNotesCharacterMaximum, magicNotesFileMaximumSize, addStudyMaterialToFolderUseCase);
        Intrinsics.checkNotNullParameter(stateHandle, "stateHandle");
        Intrinsics.checkNotNullParameter(notesEventLogger, "notesEventLogger");
        Intrinsics.checkNotNullParameter(getMeteringInfo, "getMeteringInfo");
        Intrinsics.checkNotNullParameter(createNotesToValueInfoUseCase, "createNotesToValueInfoUseCase");
        Intrinsics.checkNotNullParameter(magicNotesCharacterMinimum, "magicNotesCharacterMinimum");
        Intrinsics.checkNotNullParameter(magicNotesCharacterMaximum, "magicNotesCharacterMaximum");
        Intrinsics.checkNotNullParameter(magicNotesFileMaximumSize, "magicNotesFileMaximumSize");
        Intrinsics.checkNotNullParameter(addStudyMaterialToFolderUseCase, "addStudyMaterialToFolderUseCase");
        this.q = notesEventLogger;
        this.r = createNotesToValueInfoUseCase;
        String str = (String) stateHandle.a("text");
        this.s = str == null ? "" : str;
        this.t = e0.c(com.quizlet.features.notes.upload.states.d.a);
        this.u = EnumC4489i0.TEXT;
        this.v = com.quizlet.features.notes.data.d.a;
        this.y = "";
        do {
            s0Var = this.t;
            value = s0Var.getValue();
        } while (!s0Var.k(value, new com.quizlet.features.notes.upload.states.c(this.s, this.m, this.n)));
    }

    @Override // com.quizlet.features.notes.upload.viewmodels.c
    public final X E() {
        return this.t;
    }
}
