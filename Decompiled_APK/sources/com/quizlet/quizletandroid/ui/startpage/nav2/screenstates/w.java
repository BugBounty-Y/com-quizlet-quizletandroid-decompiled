package com.quizlet.quizletandroid.ui.startpage.nav2.screenstates;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class w extends s {
    public final long a;
    public final com.quizlet.offline.managers.j b;

    public w(long j, com.quizlet.offline.managers.j launchBehavior) {
        Intrinsics.checkNotNullParameter(launchBehavior, "launchBehavior");
        this.a = j;
        this.b = launchBehavior;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof w)) {
            return false;
        }
        w wVar = (w) obj;
        return this.a == wVar.a && this.b == wVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "ShowOfflineDialog(setId=" + this.a + ", launchBehavior=" + this.b + ")";
    }
}
