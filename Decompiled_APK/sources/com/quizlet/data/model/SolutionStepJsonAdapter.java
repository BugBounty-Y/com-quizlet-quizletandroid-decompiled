package com.quizlet.data.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SolutionStepJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;

    public SolutionStepJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("isResult", "stepNumber", "columns");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(Boolean.TYPE, m, "isResult");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(Integer.TYPE, m, "stepNumber");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(com.squareup.moshi.H.f(List.class, SolutionColumn.class), m, "columns");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Boolean bool = null;
        Integer num = null;
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                bool = (Boolean) this.b.a(reader);
                if (bool == null) {
                    throw com.squareup.moshi.internal.b.k("isResult", "isResult", reader);
                }
            } else if (iK0 == 1) {
                num = (Integer) this.c.a(reader);
                if (num == null) {
                    throw com.squareup.moshi.internal.b.k("stepNumber", "stepNumber", reader);
                }
            } else if (iK0 == 2 && (list = (List) this.d.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("columns", "columns", reader);
            }
        }
        reader.i();
        if (bool == null) {
            throw com.squareup.moshi.internal.b.e("isResult", "isResult", reader);
        }
        boolean zBooleanValue = bool.booleanValue();
        if (num == null) {
            throw com.squareup.moshi.internal.b.e("stepNumber", "stepNumber", reader);
        }
        int iIntValue = num.intValue();
        if (list != null) {
            return new SolutionStep(zBooleanValue, iIntValue, list);
        }
        throw com.squareup.moshi.internal.b.e("columns", "columns", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        SolutionStep solutionStep = (SolutionStep) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (solutionStep == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("isResult");
        this.b.g(writer, Boolean.valueOf(solutionStep.a));
        writer.l("stepNumber");
        this.c.g(writer, Integer.valueOf(solutionStep.b));
        writer.l("columns");
        this.d.g(writer, solutionStep.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(34, "GeneratedJsonAdapter(SolutionStep)", "toString(...)");
    }
}
