package com.quizlet.remote.model.notes;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class StudyNotesRequest {
    public final boolean a;

    public StudyNotesRequest(@InterfaceC4853h(name = "private") boolean z) {
        this.a = z;
    }

    @NotNull
    public final StudyNotesRequest copy(@InterfaceC4853h(name = "private") boolean z) {
        return new StudyNotesRequest(z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof StudyNotesRequest) && this.a == ((StudyNotesRequest) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("StudyNotesRequest(isPrivate="), this.a);
    }
}
