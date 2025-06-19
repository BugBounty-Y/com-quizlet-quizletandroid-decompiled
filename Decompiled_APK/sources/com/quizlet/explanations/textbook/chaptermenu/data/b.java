package com.quizlet.explanations.textbook.chaptermenu.data;

import com.quizlet.data.model.Chapter;
import com.quizlet.data.model.TableOfContentItem;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends e {
    public final Chapter a;

    public b(Chapter contentItem) {
        Intrinsics.checkNotNullParameter(contentItem, "contentItem");
        this.a = contentItem;
    }

    @Override // com.quizlet.explanations.textbook.chaptermenu.data.e
    public final TableOfContentItem a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Chapter(contentItem=" + this.a + ")";
    }
}
