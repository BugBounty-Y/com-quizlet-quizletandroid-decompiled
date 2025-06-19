package com.quizlet.search.navigation;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends l {
    public final e a;
    public final String b;

    public f(e liveMode, String str) {
        Intrinsics.checkNotNullParameter(liveMode, "liveMode");
        this.a = liveMode;
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a == fVar.a && Intrinsics.b(this.b, fVar.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        return "QuizletLive(liveMode=" + this.a + ", gameCode=" + this.b + ")";
    }
}
