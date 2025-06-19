package com.quizlet.login.signup.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p implements q {
    public final com.quizlet.ui.models.webpage.b a;

    public p(com.quizlet.ui.models.webpage.b webPage) {
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        this.a = webPage;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof p) && this.a.equals(((p) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "WebPage(webPage=" + this.a + ")";
    }
}
