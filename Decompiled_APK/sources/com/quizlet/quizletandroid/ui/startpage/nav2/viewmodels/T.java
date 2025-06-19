package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class T extends D {
    public final com.quizlet.ui.models.webpage.j a;

    public T(com.quizlet.ui.models.webpage.j webPage) {
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        this.a = webPage;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof T) && this.a.equals(((T) obj).a);
    }

    public final int hashCode() {
        return this.a.b.hashCode();
    }

    public final String toString() {
        return "ShowWebPage(webPage=" + this.a + ")";
    }
}
