package com.quizlet.shared.models.folderstudymaterials;

import androidx.compose.animation.d0;
import com.quizlet.shared.enums.p;
import com.quizlet.shared.models.explanations.ExplanationQuestion;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;
import serialization.e;

@f
@Metadata
/* loaded from: classes3.dex */
public final class FolderStudyMaterial$ExplanationQuestionMaterial extends e implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public final ExplanationQuestion b;
    public final long c;
    public final long d;
    public final String e;
    public final p f;
    public final String g;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FolderStudyMaterial$ExplanationQuestionMaterial$$serializer.INSTANCE;
        }
    }

    public FolderStudyMaterial$ExplanationQuestionMaterial(int i, ExplanationQuestion explanationQuestion, long j, long j2, String str, p pVar, String str2) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, FolderStudyMaterial$ExplanationQuestionMaterial$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = explanationQuestion;
        this.c = j;
        this.d = j2;
        if ((i & 8) == 0) {
            this.e = explanationQuestion.c;
        } else {
            this.e = str;
        }
        if ((i & 16) == 0) {
            this.f = p.f;
        } else {
            this.f = pVar;
        }
        if ((i & 32) == 0) {
            this.g = explanationQuestion.f.b;
        } else {
            this.g = str2;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FolderStudyMaterial$ExplanationQuestionMaterial)) {
            return false;
        }
        FolderStudyMaterial$ExplanationQuestionMaterial folderStudyMaterial$ExplanationQuestionMaterial = (FolderStudyMaterial$ExplanationQuestionMaterial) obj;
        return Intrinsics.b(this.b, folderStudyMaterial$ExplanationQuestionMaterial.b) && this.c == folderStudyMaterial$ExplanationQuestionMaterial.c && this.d == folderStudyMaterial$ExplanationQuestionMaterial.d;
    }

    public final int hashCode() {
        return Long.hashCode(this.d) + d0.d(this.b.hashCode() * 31, 31, this.c);
    }

    public final String toString() {
        return "ExplanationQuestionMaterial(data=" + this.b + ", id=" + this.c + ", timestampSec=" + this.d + ")";
    }
}
