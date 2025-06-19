package com.quizlet.shared.models.notes;

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
public final class EssayPromptItem extends e {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String b;
    public final com.quizlet.shared.enums.studynotes.b c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return EssayPromptItem$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ EssayPromptItem(int i, com.quizlet.shared.enums.studynotes.b bVar, String str) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, EssayPromptItem$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = str;
        this.c = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof EssayPromptItem)) {
            return false;
        }
        EssayPromptItem essayPromptItem = (EssayPromptItem) obj;
        return Intrinsics.b(this.b, essayPromptItem.b) && this.c == essayPromptItem.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + (this.b.hashCode() * 31);
    }

    public final String toString() {
        return "EssayPromptItem(prompt=" + this.b + ", difficulty=" + this.c + ")";
    }

    public EssayPromptItem(String prompt, com.quizlet.shared.enums.studynotes.b difficulty) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(difficulty, "difficulty");
        this.b = prompt;
        this.c = difficulty;
    }
}
