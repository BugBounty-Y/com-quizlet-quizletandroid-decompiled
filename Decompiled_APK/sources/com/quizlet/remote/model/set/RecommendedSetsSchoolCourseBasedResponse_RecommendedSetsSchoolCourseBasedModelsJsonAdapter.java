package com.quizlet.remote.model.set;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.set.RecommendedSetsSchoolCourseBasedResponse;
import com.quizlet.remote.model.user.RemoteUser;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
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
public final class RecommendedSetsSchoolCourseBasedResponse_RecommendedSetsSchoolCourseBasedModelsJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;

    public RecommendedSetsSchoolCourseBasedResponse_RecommendedSetsSchoolCourseBasedModelsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("recommendedStudiable", "user", "set");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, RemoteRecommendedStudiable.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "recommendedStudiable");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, RemoteUser.class), m, "user");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, RemoteSet.class), m, "set");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        List list2 = null;
        List list3 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
                if (list == null) {
                    throw com.squareup.moshi.internal.b.k("recommendedStudiable", "recommendedStudiable", reader);
                }
            } else if (iK0 == 1) {
                list2 = (List) this.c.a(reader);
                if (list2 == null) {
                    throw com.squareup.moshi.internal.b.k("user", "user", reader);
                }
            } else if (iK0 == 2 && (list3 = (List) this.d.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("set_", "set", reader);
            }
        }
        reader.i();
        if (list == null) {
            throw com.squareup.moshi.internal.b.e("recommendedStudiable", "recommendedStudiable", reader);
        }
        if (list2 == null) {
            throw com.squareup.moshi.internal.b.e("user", "user", reader);
        }
        if (list3 != null) {
            return new RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedModels(list, list2, list3);
        }
        throw com.squareup.moshi.internal.b.e("set_", "set", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedModels recommendedSetsSchoolCourseBasedModels = (RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedModels) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (recommendedSetsSchoolCourseBasedModels == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("recommendedStudiable");
        this.b.g(writer, recommendedSetsSchoolCourseBasedModels.a);
        writer.l("user");
        this.c.g(writer, recommendedSetsSchoolCourseBasedModels.b);
        writer.l("set");
        this.d.g(writer, recommendedSetsSchoolCourseBasedModels.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(101, "GeneratedJsonAdapter(RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedModels)", "toString(...)");
    }
}
