package com.quizlet.features.flashcards.settings;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class m extends c {
    public final d a;

    public m(d updates) {
        Intrinsics.checkNotNullParameter(updates, "updates");
        this.a = updates;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && Intrinsics.b(this.a, ((m) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "InProgressSettingsUpdate(updates=" + this.a + ")";
    }
}
