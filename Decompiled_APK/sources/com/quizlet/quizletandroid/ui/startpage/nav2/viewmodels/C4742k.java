package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4742k extends M {
    public final long a;

    public C4742k(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4742k) && this.a == ((C4742k) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("GoToAddSetToFolder(setId="));
    }
}
