package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4744m extends D {
    public final long a;

    public C4744m(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4744m) && this.a == ((C4744m) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("GoToFolder(id="));
    }
}
