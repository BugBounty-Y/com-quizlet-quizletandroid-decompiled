package com.quizlet.remote.model.set;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.base.ModelError;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.base.ValidationError;
import com.quizlet.remote.model.set.RecommendedSetsBehaviorBasedResponse;
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
public final class RecommendedSetsBehaviorBasedResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;

    public RecommendedSetsBehaviorBasedResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("models", "source", "paging", "validationErrors", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(RecommendedSetsBehaviorBasedResponse.RecommendedSetsBehaviorBasedModels.class, m, "models");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(RecommendedSetsBehaviorBasedResponse.RecommendedSetsBehaviorBasedSource.class, m, "source");
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
        RecommendedSetsBehaviorBasedResponse.RecommendedSetsBehaviorBasedModels recommendedSetsBehaviorBasedModels = null;
        PagingInfo pagingInfo = null;
        List list = null;
        ModelError modelError = null;
        boolean z = false;
        boolean z2 = false;
        boolean z3 = false;
        RecommendedSetsBehaviorBasedResponse.RecommendedSetsBehaviorBasedSource recommendedSetsBehaviorBasedSource = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                recommendedSetsBehaviorBasedModels = (RecommendedSetsBehaviorBasedResponse.RecommendedSetsBehaviorBasedModels) this.b.a(reader);
            } else if (iK0 == 1) {
                recommendedSetsBehaviorBasedSource = (RecommendedSetsBehaviorBasedResponse.RecommendedSetsBehaviorBasedSource) this.c.a(reader);
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
        RecommendedSetsBehaviorBasedResponse recommendedSetsBehaviorBasedResponse = new RecommendedSetsBehaviorBasedResponse(recommendedSetsBehaviorBasedModels, recommendedSetsBehaviorBasedSource);
        if (z) {
            recommendedSetsBehaviorBasedResponse.a = pagingInfo;
        }
        if (z2) {
            recommendedSetsBehaviorBasedResponse.b = list;
        }
        if (z3) {
            recommendedSetsBehaviorBasedResponse.c = modelError;
        }
        return recommendedSetsBehaviorBasedResponse;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RecommendedSetsBehaviorBasedResponse recommendedSetsBehaviorBasedResponse = (RecommendedSetsBehaviorBasedResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (recommendedSetsBehaviorBasedResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("models");
        this.b.g(writer, recommendedSetsBehaviorBasedResponse.d);
        writer.l("source");
        this.c.g(writer, recommendedSetsBehaviorBasedResponse.e);
        writer.l("paging");
        this.d.g(writer, recommendedSetsBehaviorBasedResponse.a);
        writer.l("validationErrors");
        this.e.g(writer, recommendedSetsBehaviorBasedResponse.b);
        writer.l("error");
        this.f.g(writer, recommendedSetsBehaviorBasedResponse.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(58, "GeneratedJsonAdapter(RecommendedSetsBehaviorBasedResponse)", "toString(...)");
    }
}
