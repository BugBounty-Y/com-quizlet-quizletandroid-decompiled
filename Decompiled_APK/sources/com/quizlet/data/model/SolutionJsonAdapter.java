package com.quizlet.data.model;

import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SolutionJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;

    public SolutionJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("steps", "totalSteps");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = com.squareup.moshi.H.f(List.class, SolutionStep.class);
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "steps");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(Integer.TYPE, m, "totalSteps");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        Integer num = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
                if (list == null) {
                    throw com.squareup.moshi.internal.b.k("steps", "steps", reader);
                }
            } else if (iK0 == 1 && (num = (Integer) this.c.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("totalSteps", "totalSteps", reader);
            }
        }
        reader.i();
        if (list == null) {
            throw com.squareup.moshi.internal.b.e("steps", "steps", reader);
        }
        if (num != null) {
            return new Solution(list, num.intValue());
        }
        throw com.squareup.moshi.internal.b.e("totalSteps", "totalSteps", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        Solution solution = (Solution) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (solution == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("steps");
        this.b.g(writer, solution.a);
        writer.l("totalSteps");
        this.c.g(writer, Integer.valueOf(solution.b));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(30, "GeneratedJsonAdapter(Solution)", "toString(...)");
    }
}
