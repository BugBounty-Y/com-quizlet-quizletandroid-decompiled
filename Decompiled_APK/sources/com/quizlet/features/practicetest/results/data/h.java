package com.quizlet.features.practicetest.results.data;

/* loaded from: classes3.dex */
public final class h implements n {
    public final boolean a;

    public h(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof h) && this.a == ((h) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("QuestionListClicked(isOpened="), this.a);
    }
}
