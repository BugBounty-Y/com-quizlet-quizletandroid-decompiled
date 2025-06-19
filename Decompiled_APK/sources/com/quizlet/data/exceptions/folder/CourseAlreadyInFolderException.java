package com.quizlet.data.exceptions.folder;

import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class CourseAlreadyInFolderException extends IllegalStateException {
    public CourseAlreadyInFolderException() {
        super("Course already in folder");
    }
}
