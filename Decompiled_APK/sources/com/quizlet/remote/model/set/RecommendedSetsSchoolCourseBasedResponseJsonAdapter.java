package com.quizlet.remote.model.set;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.base.ModelError;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.base.ValidationError;
import com.quizlet.remote.model.set.RecommendedSetsSchoolCourseBasedResponse;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RecommendedSetsSchoolCourseBasedResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;

    public RecommendedSetsSchoolCourseBasedResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("models", "source", "paging", "validationErrors", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedModels.class, m, "models");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedSource.class, m, "source");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(PagingInfo.class, m, "pagingInfo");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(H.f(List.class, ValidationError.class), m, "validationErrors");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(ModelError.class, m, "error");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedModels recommendedSetsSchoolCourseBasedModels = null;
        PagingInfo pagingInfo = null;
        List list = null;
        ModelError modelError = null;
        boolean z = false;
        boolean z2 = false;
        boolean z3 = false;
        RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedSource recommendedSetsSchoolCourseBasedSource = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                recommendedSetsSchoolCourseBasedModels = (RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedModels) this.b.a(reader);
                if (recommendedSetsSchoolCourseBasedModels == null) {
                    throw com.squareup.moshi.internal.b.k("models", "models", reader);
                }
            } else if (iK0 == 1) {
                recommendedSetsSchoolCourseBasedSource = (RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedSource) this.c.a(reader);
                if (recommendedSetsSchoolCourseBasedSource == null) {
                    throw com.squareup.moshi.internal.b.k("source", "source", reader);
                }
            } else if (iK0 == 2) {
                pagingInfo = (PagingInfo) this.d.a(reader);
                z = true;
            } else if (iK0 == 3) {
                list = (List) this.e.a(reader);
                z2 = true;
            } else if (iK0 == 4) {
                modelError = (ModelError) this.f.a(reader);
                z3 = true;
            }
        }
        reader.i();
        if (recommendedSetsSchoolCourseBasedModels == null) {
            throw com.squareup.moshi.internal.b.e("models", "models", reader);
        }
        if (recommendedSetsSchoolCourseBasedSource == null) {
            throw com.squareup.moshi.internal.b.e("source", "source", reader);
        }
        RecommendedSetsSchoolCourseBasedResponse recommendedSetsSchoolCourseBasedResponse = new RecommendedSetsSchoolCourseBasedResponse(recommendedSetsSchoolCourseBasedModels, recommendedSetsSchoolCourseBasedSource);
        if (z) {
            recommendedSetsSchoolCourseBasedResponse.a = pagingInfo;
        }
        if (z2) {
            recommendedSetsSchoolCourseBasedResponse.b = list;
        }
        if (z3) {
            recommendedSetsSchoolCourseBasedResponse.c = modelError;
        }
        return recommendedSetsSchoolCourseBasedResponse;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RecommendedSetsSchoolCourseBasedResponse recommendedSetsSchoolCourseBasedResponse = (RecommendedSetsSchoolCourseBasedResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (recommendedSetsSchoolCourseBasedResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("models");
        this.b.g(writer, recommendedSetsSchoolCourseBasedResponse.d);
        writer.l("source");
        this.c.g(writer, recommendedSetsSchoolCourseBasedResponse.e);
        writer.l("paging");
        this.d.g(writer, recommendedSetsSchoolCourseBasedResponse.a);
        writer.l("validationErrors");
        this.e.g(writer, recommendedSetsSchoolCourseBasedResponse.b);
        writer.l("error");
        this.f.g(writer, recommendedSetsSchoolCourseBasedResponse.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(62, "GeneratedJsonAdapter(RecommendedSetsSchoolCourseBasedResponse)", "toString(...)");
    }
}
