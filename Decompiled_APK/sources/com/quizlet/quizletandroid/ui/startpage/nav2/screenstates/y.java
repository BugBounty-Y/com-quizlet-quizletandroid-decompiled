package com.quizlet.quizletandroid.ui.startpage.nav2.screenstates;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y extends s {
    public final com.quizlet.ui.models.webpage.j a;

    public y(com.quizlet.ui.models.webpage.j webPage) {
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        this.a = webPage;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof y) && this.a.equals(((y) obj).a);
    }

    public final int hashCode() {
        return this.a.b.hashCode();
    }

    public final String toString() {
        return "ShowWebPage(webPage=" + this.a + ")";
    }
}
