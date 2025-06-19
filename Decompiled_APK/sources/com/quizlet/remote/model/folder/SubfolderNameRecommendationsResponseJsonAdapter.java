package com.quizlet.remote.model.folder;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.base.ModelError;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.base.ValidationError;
import com.quizlet.remote.model.folder.SubfolderNameRecommendationsResponse;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.w;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SubfolderNameRecommendationsResponseJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;

    public SubfolderNameRecommendationsResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("models", "paging", "validationErrors", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        com.squareup.moshi.l lVarA = moshi.a(SubfolderNameRecommendationsResponse.Models.class, m, "models");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(PagingInfo.class, m, "pagingInfo");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(H.f(List.class, ValidationError.class), m, "validationErrors");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(ModelError.class, m, "error");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        SubfolderNameRecommendationsResponse.Models models = null;
        List list = null;
        ModelError modelError = null;
        boolean z = false;
        boolean z2 = false;
        boolean z3 = false;
        PagingInfo pagingInfo = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                models = (SubfolderNameRecommendationsResponse.Models) this.b.a(reader);
            } else if (iK0 == 1) {
                pagingInfo = (PagingInfo) this.c.a(reader);
                z = true;
            } else if (iK0 == 2) {
                list = (List) this.d.a(reader);
                z2 = true;
            } else if (iK0 == 3) {
                modelError = (ModelError) this.e.a(reader);
                z3 = true;
            }
        }
        reader.i();
        SubfolderNameRecommendationsResponse subfolderNameRecommendationsResponse = new SubfolderNameRecommendationsResponse(models);
        if (z) {
            subfolderNameRecommendationsResponse.a = pagingInfo;
        }
        if (z2) {
            subfolderNameRecommendationsResponse.b = list;
        }
        if (z3) {
            subfolderNameRecommendationsResponse.c = modelError;
        }
        return subfolderNameRecommendationsResponse;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SubfolderNameRecommendationsResponse subfolderNameRecommendationsResponse = (SubfolderNameRecommendationsResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (subfolderNameRecommendationsResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("models");
        this.b.g(writer, subfolderNameRecommendationsResponse.d);
        writer.l("paging");
        this.c.g(writer, subfolderNameRecommendationsResponse.a);
        writer.l("validationErrors");
        this.d.g(writer, subfolderNameRecommendationsResponse.b);
        writer.l("error");
        this.e.g(writer, subfolderNameRecommendationsResponse.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(58, "GeneratedJsonAdapter(SubfolderNameRecommendationsResponse)", "toString(...)");
    }
}
