package com.quizlet.data.repository.school.exceptions;

import java.io.IOException;
import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class CreateNewSchoolException extends IOException {
    public CreateNewSchoolException() {
        super("Could not create school.");
    }
}
