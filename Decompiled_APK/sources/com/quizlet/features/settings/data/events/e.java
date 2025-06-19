package com.quizlet.features.settings.data.events;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements h {
    public final com.quizlet.ui.models.webpage.b a;

    public e(com.quizlet.ui.models.webpage.b webPage) {
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        this.a = webPage;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof e) && this.a.equals(((e) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "GoToWebPage(webPage=" + this.a + ")";
    }
}
