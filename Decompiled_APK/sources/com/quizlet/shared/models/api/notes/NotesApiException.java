package com.quizlet.shared.models.api.notes;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public class NotesApiException extends Exception {
    public final boolean equals(Object obj) {
        return (obj instanceof NotesApiException) && Intrinsics.b(getMessage(), ((NotesApiException) obj).getMessage());
    }

    public final int hashCode() {
        String message = getMessage();
        if (message != null) {
            return message.hashCode();
        }
        return 0;
    }
}
