package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class FlashcardsTermDefinitionCardJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;

    public FlashcardsTermDefinitionCardJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("term", "definition");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        com.squareup.moshi.l lVarA = moshi.a(String.class, kotlin.collections.M.a, "term");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                com.squareup.moshi.l lVar = this.b;
                if (iK0 == 0) {
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("term", "term", reader);
                    }
                } else if (iK0 == 1 && (str2 = (String) lVar.a(reader)) == null) {
                    throw com.squareup.moshi.internal.b.k("definition", "definition", reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("term", "term", reader);
        }
        if (str2 != null) {
            return new FlashcardsTermDefinitionCard(str, str2);
        }
        throw com.squareup.moshi.internal.b.e("definition", "definition", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        FlashcardsTermDefinitionCard flashcardsTermDefinitionCard = (FlashcardsTermDefinitionCard) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (flashcardsTermDefinitionCard == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("term");
        com.squareup.moshi.l lVar = this.b;
        lVar.g(writer, flashcardsTermDefinitionCard.a);
        writer.l("definition");
        lVar.g(writer, flashcardsTermDefinitionCard.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(50, "GeneratedJsonAdapter(FlashcardsTermDefinitionCard)", "toString(...)");
    }
}
