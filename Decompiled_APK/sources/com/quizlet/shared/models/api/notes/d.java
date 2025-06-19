package com.quizlet.shared.models.api.notes;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final String a;

    public d(String uuid) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        this.a = uuid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && Intrinsics.b(this.a, ((d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("StudyNotesArtifactRequest(uuid="), this.a, ")");
    }
}
