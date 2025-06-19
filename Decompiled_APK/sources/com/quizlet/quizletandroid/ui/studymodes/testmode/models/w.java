package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

/* loaded from: classes3.dex */
public final class w {
    public final long a;

    public w(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof w) && this.a == ((w) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("TestStarted(sessionId="));
    }
}
