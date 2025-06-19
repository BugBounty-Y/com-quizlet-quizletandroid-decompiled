package com.quizlet.data.exceptions.user;

import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class LoggedInRequiredException extends IllegalStateException {
    public LoggedInRequiredException() {
        super("Operation requires user to be logged in.");
    }
}
