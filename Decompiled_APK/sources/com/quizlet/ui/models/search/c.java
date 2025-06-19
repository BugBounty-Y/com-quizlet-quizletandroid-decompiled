package com.quizlet.ui.models.search;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements a {
    public final com.quizlet.data.model.search.c a;

    public c(com.quizlet.data.model.search.c banner) {
        Intrinsics.checkNotNullParameter(banner, "banner");
        this.a = banner;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && Intrinsics.b(this.a, ((c) obj).a);
    }

    @Override // com.quizlet.ui.models.search.a
    public final Object getKey() {
        com.quizlet.data.model.search.c cVar = this.a;
        return android.support.v4.media.session.a.m("searchShortcut:", cVar.c.a(), "-", cVar.b);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SearchShortcutUiModel(banner=" + this.a + ")";
    }
}
