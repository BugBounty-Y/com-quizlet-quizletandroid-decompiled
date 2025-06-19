package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class EssayItem {
    public final String a;
    public final T b;

    public EssayItem(String prompt, T difficulty) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(difficulty, "difficulty");
        this.a = prompt;
        this.b = difficulty;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof EssayItem)) {
            return false;
        }
        EssayItem essayItem = (EssayItem) obj;
        return Intrinsics.b(this.a, essayItem.a) && this.b == essayItem.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "EssayItem(prompt=" + this.a + ", difficulty=" + this.b + ")";
    }
}
