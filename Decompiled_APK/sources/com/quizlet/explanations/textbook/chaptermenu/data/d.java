package com.quizlet.explanations.textbook.chaptermenu.data;

import com.quizlet.data.model.Section;
import com.quizlet.data.model.TableOfContentItem;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d extends e {
    public final Section a;

    public d(Section contentItem) {
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
        return (obj instanceof d) && Intrinsics.b(this.a, ((d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Section(contentItem=" + this.a + ")";
    }
}
