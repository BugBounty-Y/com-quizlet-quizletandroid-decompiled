package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class NoSchoolException extends Exception {
    public final com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e a;

    public NoSchoolException(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e defaultSchool) {
        Intrinsics.checkNotNullParameter(defaultSchool, "defaultSchool");
        this.a = defaultSchool;
    }
}
