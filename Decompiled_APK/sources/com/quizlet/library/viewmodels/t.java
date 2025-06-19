package com.quizlet.library.viewmodels;

import com.quizlet.data.model.S0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class t implements e {
    public final S0 a;
    public final com.quizlet.ui.models.content.listitem.g b;
    public final String c;

    public t(S0 cardModel, com.quizlet.ui.models.content.listitem.g contentMetadata) {
        Intrinsics.checkNotNullParameter(cardModel, "cardModel");
        Intrinsics.checkNotNullParameter(contentMetadata, "contentMetadata");
        this.a = cardModel;
        this.b = contentMetadata;
        this.c = contentMetadata.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof t)) {
            return false;
        }
        t tVar = (t) obj;
        return Intrinsics.b(this.a, tVar.a) && Intrinsics.b(this.b, tVar.b);
    }

    @Override // com.quizlet.library.viewmodels.e
    public final String getKey() {
        return this.c;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "PracticeTestData(cardModel=" + this.a + ", contentMetadata=" + this.b + ")";
    }
}
