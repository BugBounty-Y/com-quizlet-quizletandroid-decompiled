package com.quizlet.features.notes.detail.events;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k implements p {
    public final String a;

    public k(String magicNoteUuid) {
        Intrinsics.checkNotNullParameter(magicNoteUuid, "magicNoteUuid");
        this.a = magicNoteUuid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof k) && Intrinsics.b(this.a, ((k) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("ReportContent(magicNoteUuid="), this.a, ")");
    }
}
