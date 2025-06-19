package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SolutionColumnJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;

    public SolutionColumnJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("text", "hasInvalidKatex", "images");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(String.class, m, "text");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(Boolean.TYPE, m, "hasInvalidKatex");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(SolutionColumnImages.class, m, "images");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        Boolean bool = null;
        SolutionColumnImages solutionColumnImages = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                str = (String) this.b.a(reader);
                if (str == null) {
                    throw com.squareup.moshi.internal.b.k("text", "text", reader);
                }
            } else if (iK0 == 1) {
                bool = (Boolean) this.c.a(reader);
                if (bool == null) {
                    throw com.squareup.moshi.internal.b.k("hasInvalidKatex", "hasInvalidKatex", reader);
                }
            } else if (iK0 == 2 && (solutionColumnImages = (SolutionColumnImages) this.d.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("images", "images", reader);
            }
        }
        reader.i();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("text", "text", reader);
        }
        if (bool == null) {
            throw com.squareup.moshi.internal.b.e("hasInvalidKatex", "hasInvalidKatex", reader);
        }
        boolean zBooleanValue = bool.booleanValue();
        if (solutionColumnImages != null) {
            return new SolutionColumn(str, zBooleanValue, solutionColumnImages);
        }
        throw com.squareup.moshi.internal.b.e("images", "images", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        SolutionColumn solutionColumn = (SolutionColumn) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (solutionColumn == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("text");
        this.b.g(writer, solutionColumn.a);
        writer.l("hasInvalidKatex");
        this.c.g(writer, Boolean.valueOf(solutionColumn.b));
        writer.l("images");
        this.d.g(writer, solutionColumn.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(36, "GeneratedJsonAdapter(SolutionColumn)", "toString(...)");
    }
}
