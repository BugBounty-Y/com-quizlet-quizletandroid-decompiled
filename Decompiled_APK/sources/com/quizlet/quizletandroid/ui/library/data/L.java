package com.quizlet.quizletandroid.ui.library.data;

import androidx.compose.animation.d0;
import com.quizlet.data.model.Y1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class L implements K {
    public final com.quizlet.ui.models.content.carditem.f a;
    public final com.quizlet.ui.models.content.listitem.d b;
    public final long c;
    public final Y1 d;
    public final long e;

    public L(com.quizlet.ui.models.content.carditem.f studySetCardModel, com.quizlet.ui.models.content.listitem.d flashcardSetContentMetadata, long j, Y1 type) {
        Intrinsics.checkNotNullParameter(studySetCardModel, "studySetCardModel");
        Intrinsics.checkNotNullParameter(flashcardSetContentMetadata, "flashcardSetContentMetadata");
        Intrinsics.checkNotNullParameter(type, "type");
        this.a = studySetCardModel;
        this.b = flashcardSetContentMetadata;
        this.c = j;
        this.d = type;
        this.e = flashcardSetContentMetadata.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof L)) {
            return false;
        }
        L l = (L) obj;
        return Intrinsics.b(this.a, l.a) && Intrinsics.b(this.b, l.b) && this.c == l.c && this.d == l.d;
    }

    @Override // com.quizlet.quizletandroid.ui.library.data.K
    public final Object getKey() {
        return Long.valueOf(this.e);
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.d((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c);
    }

    public final String toString() {
        return "StudySetListItem(studySetCardModel=" + this.a + ", flashcardSetContentMetadata=" + this.b + ", sortTimestamp=" + this.c + ", type=" + this.d + ")";
    }
}
