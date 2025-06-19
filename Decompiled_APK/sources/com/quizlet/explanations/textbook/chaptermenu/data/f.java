package com.quizlet.explanations.textbook.chaptermenu.data;

import com.quizlet.data.model.TableOfContentItem;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f extends a {
    public final TableOfContentItem a;

    public f(TableOfContentItem data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && Intrinsics.b(this.a, ((f) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "GoToChapterMenu(data=" + this.a + ")";
    }
}
