package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class RecommendedStudyMaterialJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;

    public RecommendedStudyMaterialJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("studyMaterialId", "studyMaterialType", "rank", "isPeerRec");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(String.class, m, "studyMaterialId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(com.quizlet.generated.enums.y1.class, m, "studyMaterialType");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(Integer.TYPE, m, "rank");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(Boolean.TYPE, m, "isPeerRec");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        com.quizlet.generated.enums.y1 y1Var = null;
        Integer num = null;
        Boolean bool = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                str = (String) this.b.a(reader);
                if (str == null) {
                    throw com.squareup.moshi.internal.b.k("studyMaterialId", "studyMaterialId", reader);
                }
            } else if (iK0 == 1) {
                y1Var = (com.quizlet.generated.enums.y1) this.c.a(reader);
                if (y1Var == null) {
                    throw com.squareup.moshi.internal.b.k("studyMaterialType", "studyMaterialType", reader);
                }
            } else if (iK0 == 2) {
                num = (Integer) this.d.a(reader);
                if (num == null) {
                    throw com.squareup.moshi.internal.b.k("rank", "rank", reader);
                }
            } else if (iK0 == 3 && (bool = (Boolean) this.e.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("isPeerRec", "isPeerRec", reader);
            }
        }
        reader.i();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("studyMaterialId", "studyMaterialId", reader);
        }
        if (y1Var == null) {
            throw com.squareup.moshi.internal.b.e("studyMaterialType", "studyMaterialType", reader);
        }
        if (num == null) {
            throw com.squareup.moshi.internal.b.e("rank", "rank", reader);
        }
        int iIntValue = num.intValue();
        if (bool != null) {
            return new RecommendedStudyMaterial(str, y1Var, iIntValue, bool.booleanValue());
        }
        throw com.squareup.moshi.internal.b.e("isPeerRec", "isPeerRec", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        RecommendedStudyMaterial recommendedStudyMaterial = (RecommendedStudyMaterial) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (recommendedStudyMaterial == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("studyMaterialId");
        this.b.g(writer, recommendedStudyMaterial.a);
        writer.l("studyMaterialType");
        this.c.g(writer, recommendedStudyMaterial.b);
        writer.l("rank");
        this.d.g(writer, Integer.valueOf(recommendedStudyMaterial.c));
        writer.l("isPeerRec");
        this.e.g(writer, Boolean.valueOf(recommendedStudyMaterial.d));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(46, "GeneratedJsonAdapter(RecommendedStudyMaterial)", "toString(...)");
    }
}
