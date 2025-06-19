package com.quizlet.features.flashcards.settings;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends c {
    public final d a;

    public b(d updates) {
        Intrinsics.checkNotNullParameter(updates, "updates");
        this.a = updates;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ClosingSettingsUpdate(updates=" + this.a + ")";
    }
}
