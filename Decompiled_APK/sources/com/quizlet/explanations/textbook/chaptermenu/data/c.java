package com.quizlet.explanations.textbook.chaptermenu.data;

import com.quizlet.data.model.ExerciseGroup;
import com.quizlet.data.model.TableOfContentItem;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends e {
    public final ExerciseGroup a;

    public c(ExerciseGroup contentItem) {
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
        return (obj instanceof c) && Intrinsics.b(this.a, ((c) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ExerciseGroup(contentItem=" + this.a + ")";
    }
}
