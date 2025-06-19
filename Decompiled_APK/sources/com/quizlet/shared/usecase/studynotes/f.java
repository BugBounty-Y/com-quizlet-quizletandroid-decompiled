package com.quizlet.shared.usecase.studynotes;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements q {
    public final com.quizlet.shared.repository.d a;
    public final kotlinx.serialization.json.c b;

    public f(com.quizlet.shared.repository.d termRepository, kotlinx.serialization.json.c json) {
        Intrinsics.checkNotNullParameter(termRepository, "termRepository");
        Intrinsics.checkNotNullParameter(json, "json");
        this.a = termRepository;
        this.b = json;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(com.quizlet.shared.models.api.notes.StudyNotesArtifactsResponse r17, kotlin.coroutines.jvm.internal.c r18) {
        /*
            Method dump skipped, instructions count: 540
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.studynotes.f.a(com.quizlet.shared.models.api.notes.StudyNotesArtifactsResponse, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
