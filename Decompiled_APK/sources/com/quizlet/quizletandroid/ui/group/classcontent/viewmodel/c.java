package com.quizlet.quizletandroid.ui.group.classcontent.viewmodel;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends d {
    public final long a;
    public final com.quizlet.offline.managers.j b;

    public c(long j, com.quizlet.offline.managers.j launchBehavior) {
        Intrinsics.checkNotNullParameter(launchBehavior, "launchBehavior");
        this.a = j;
        this.b = launchBehavior;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && this.b == cVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "OfflineSet(setId=" + this.a + ", launchBehavior=" + this.b + ")";
    }
}
