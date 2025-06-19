package com.quizlet.data.repository.course.exceptions;

import java.io.IOException;
import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class CreateNewCourseException extends IOException {
    public CreateNewCourseException() {
        super("Could not create a new course.");
    }
}
