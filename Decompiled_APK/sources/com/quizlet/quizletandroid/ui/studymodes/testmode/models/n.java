package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.e7;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n extends e7 {
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f b;
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f c;
    public final int d;
    public final Integer e;

    public n(com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f expectedAnswer, com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f submittedAnswer, int i, Integer num) {
        Intrinsics.checkNotNullParameter(expectedAnswer, "expectedAnswer");
        Intrinsics.checkNotNullParameter(submittedAnswer, "submittedAnswer");
        this.b = expectedAnswer;
        this.c = submittedAnswer;
        this.d = i;
        this.e = num;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.e7
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f a() {
        return this.b;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.e7
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f b() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return Intrinsics.b(this.b, nVar.b) && Intrinsics.b(this.c, nVar.c) && this.d == nVar.d && Intrinsics.b(this.e, nVar.e);
    }

    public final int hashCode() {
        int iB = d0.b(this.d, (this.c.hashCode() + (this.b.hashCode() * 31)) * 31, 31);
        Integer num = this.e;
        return iB + (num == null ? 0 : num.hashCode());
    }

    public final String toString() {
        return "TrueFalse(expectedAnswer=" + this.b + ", submittedAnswer=" + this.c + ", expectedText=" + this.d + ", submittedText=" + this.e + ")";
    }
}
