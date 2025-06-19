package com.quizlet.search.navigation;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends l {
    public final com.quizlet.ui.models.webpage.k a;

    public c(com.quizlet.ui.models.webpage.k webPage) {
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        this.a = webPage;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && this.a.equals(((c) obj).a);
    }

    public final int hashCode() {
        return this.a.b.hashCode();
    }

    public final String toString() {
        return "GoToWebPage(webPage=" + this.a + ")";
    }
}
