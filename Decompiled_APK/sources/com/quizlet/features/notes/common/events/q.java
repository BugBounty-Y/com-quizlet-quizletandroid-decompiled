package com.quizlet.features.notes.common.events;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q implements y {
    public final String a;

    public q(String newTitle) {
        Intrinsics.checkNotNullParameter(newTitle, "newTitle");
        this.a = newTitle;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof q) && Intrinsics.b(this.a, ((q) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("NotesTitleEdited(newTitle="), this.a, ")");
    }
}
