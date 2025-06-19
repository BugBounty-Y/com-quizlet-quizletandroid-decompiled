package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SolutionColumnImagesJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;

    public SolutionColumnImagesJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("latex", "additional");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        com.squareup.moshi.l lVarA = moshi.a(SolutionColumnImage.class, kotlin.collections.M.a, "latex");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        SolutionColumnImage solutionColumnImage = null;
        SolutionColumnImage solutionColumnImage2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                com.squareup.moshi.l lVar = this.b;
                if (iK0 == 0) {
                    solutionColumnImage = (SolutionColumnImage) lVar.a(reader);
                } else if (iK0 == 1) {
                    solutionColumnImage2 = (SolutionColumnImage) lVar.a(reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        return new SolutionColumnImages(solutionColumnImage, solutionColumnImage2);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        SolutionColumnImages solutionColumnImages = (SolutionColumnImages) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (solutionColumnImages == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("latex");
        com.squareup.moshi.l lVar = this.b;
        lVar.g(writer, solutionColumnImages.a);
        writer.l("additional");
        lVar.g(writer, solutionColumnImages.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(42, "GeneratedJsonAdapter(SolutionColumnImages)", "toString(...)");
    }
}
