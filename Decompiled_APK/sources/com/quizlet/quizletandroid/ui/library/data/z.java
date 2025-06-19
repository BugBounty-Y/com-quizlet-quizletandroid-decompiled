package com.quizlet.quizletandroid.ui.library.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z extends F {
    public final long a;
    public final com.quizlet.offline.managers.j b;

    public z(long j, com.quizlet.offline.managers.j launchBehavior) {
        Intrinsics.checkNotNullParameter(launchBehavior, "launchBehavior");
        this.a = j;
        this.b = launchBehavior;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof z)) {
            return false;
        }
        z zVar = (z) obj;
        return this.a == zVar.a && this.b == zVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "OfflineDialog(studySetId=" + this.a + ", launchBehavior=" + this.b + ")";
    }
}
