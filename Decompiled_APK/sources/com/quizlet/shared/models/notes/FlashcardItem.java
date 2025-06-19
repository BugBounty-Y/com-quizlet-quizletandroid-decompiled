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
public final class FlashcardItem extends e {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String b;
    public final String c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FlashcardItem$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FlashcardItem(int i, String str, String str2) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, FlashcardItem$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = str;
        this.c = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardItem)) {
            return false;
        }
        FlashcardItem flashcardItem = (FlashcardItem) obj;
        return Intrinsics.b(this.b, flashcardItem.b) && Intrinsics.b(this.c, flashcardItem.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + (this.b.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlashcardItem(term=");
        sb.append(this.b);
        sb.append(", definition=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }

    public FlashcardItem(String term, String definition) {
        Intrinsics.checkNotNullParameter(term, "term");
        Intrinsics.checkNotNullParameter(definition, "definition");
        this.b = term;
        this.c = definition;
    }
}
