package com.quizlet.quizletandroid.ui.library.data;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class M implements K {
    public final long a;
    public final String b;

    public M(long j) {
        this.a = j;
        this.b = d0.n(j, "section_");
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof M) && this.a == ((M) obj).a;
    }

    @Override // com.quizlet.quizletandroid.ui.library.data.K
    public final Object getKey() {
        return this.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("StudySetListSection(section="));
    }
}
