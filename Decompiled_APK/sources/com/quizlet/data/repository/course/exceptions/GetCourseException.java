package com.quizlet.data.repository.course.exceptions;

import java.io.IOException;
import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class GetCourseException extends IOException {
    public GetCourseException() {
        super("Could not get a created course.");
    }
}
