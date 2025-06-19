package com.quizlet.quizletandroid.ui.library.data;

/* loaded from: classes3.dex */
public final class t extends F {
    public final long a;

    public t(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof t) && this.a == ((t) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("Folder(folderId="));
    }
}
