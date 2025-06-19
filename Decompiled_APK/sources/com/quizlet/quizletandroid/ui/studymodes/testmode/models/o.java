package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

import com.google.android.gms.internal.mlkit_vision_document_scanner.f7;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o extends f7 {
    public final DefaultQuestionSectionData b;
    public final DefaultQuestionSectionData c;

    public o(DefaultQuestionSectionData prompt, DefaultQuestionSectionData defaultQuestionSectionData) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        this.b = prompt;
        this.c = defaultQuestionSectionData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return Intrinsics.b(this.b, oVar.b) && Intrinsics.b(this.c, oVar.c);
    }

    public final int hashCode() {
        int iHashCode = this.b.hashCode() * 31;
        DefaultQuestionSectionData defaultQuestionSectionData = this.c;
        return iHashCode + (defaultQuestionSectionData == null ? 0 : defaultQuestionSectionData.hashCode());
    }

    public final String toString() {
        return "Default(prompt=" + this.b + ", secondPrompt=" + this.c + ")";
    }
}
