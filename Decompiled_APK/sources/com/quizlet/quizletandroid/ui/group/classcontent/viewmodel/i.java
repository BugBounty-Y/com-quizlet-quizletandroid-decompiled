package com.quizlet.quizletandroid.ui.group.classcontent.viewmodel;

/* loaded from: classes3.dex */
public final class i extends l {
    public final long a;

    public i(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof i) && this.a == ((i) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("AddSetToClass(classId="));
    }
}
