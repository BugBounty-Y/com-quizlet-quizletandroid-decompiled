package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class FlashcardsTermDefinitionCard {
    public final String a;
    public final String b;

    public FlashcardsTermDefinitionCard(String term, String definition) {
        Intrinsics.checkNotNullParameter(term, "term");
        Intrinsics.checkNotNullParameter(definition, "definition");
        this.a = term;
        this.b = definition;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsTermDefinitionCard)) {
            return false;
        }
        FlashcardsTermDefinitionCard flashcardsTermDefinitionCard = (FlashcardsTermDefinitionCard) obj;
        return Intrinsics.b(this.a, flashcardsTermDefinitionCard.a) && Intrinsics.b(this.b, flashcardsTermDefinitionCard.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlashcardsTermDefinitionCard(term=");
        sb.append(this.a);
        sb.append(", definition=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
