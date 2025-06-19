package com.quizlet.library.viewmodels;

import androidx.lifecycle.w0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.Y;

@Metadata
/* loaded from: classes3.dex */
public final class d extends w0 implements c {
    public final com.quizlet.data.interactor.notes.f b;
    public final com.quizlet.quizletandroid.k c;
    public final long d;
    public Y e;

    public d(com.quizlet.data.interactor.notes.f getAllStudyNotesUseCase, com.quizlet.quizletandroid.k getBucketedStudyNotesBySectionsUseCase, long j) {
        Intrinsics.checkNotNullParameter(getAllStudyNotesUseCase, "getAllStudyNotesUseCase");
        Intrinsics.checkNotNullParameter(getBucketedStudyNotesBySectionsUseCase, "getBucketedStudyNotesBySectionsUseCase");
        this.b = getAllStudyNotesUseCase;
        this.c = getBucketedStudyNotesBySectionsUseCase;
        this.d = j;
    }
}
