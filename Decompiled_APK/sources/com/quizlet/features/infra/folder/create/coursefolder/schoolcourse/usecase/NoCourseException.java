package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class NoCourseException extends Exception {
    public final com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c a;

    public NoCourseException(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c defaultCourse) {
        Intrinsics.checkNotNullParameter(defaultCourse, "defaultCourse");
        this.a = defaultCourse;
    }
}
