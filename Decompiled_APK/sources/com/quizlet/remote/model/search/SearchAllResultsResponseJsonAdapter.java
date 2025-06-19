package com.quizlet.remote.model.search;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.base.ModelError;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.base.ValidationError;
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
public final class SearchAllResultsResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public final l g;

    public SearchAllResultsResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("models", "associations", "shelfRanking", "paging", "validationErrors", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(RemoteAllResultsModels.class, m, "models");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(RemoteAllResultsAssociationModels.class, m, "associations");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, String.class), m, "shelfRanking");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(PagingInfo.class, m, "pagingInfo");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(H.f(List.class, ValidationError.class), m, "validationErrors");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(ModelError.class, m, "error");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        RemoteAllResultsModels remoteAllResultsModels = null;
        List list = null;
        PagingInfo pagingInfo = null;
        List list2 = null;
        ModelError modelError = null;
        boolean z = false;
        boolean z2 = false;
        boolean z3 = false;
        RemoteAllResultsAssociationModels remoteAllResultsAssociationModels = null;
        while (reader.l()) {
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    remoteAllResultsModels = (RemoteAllResultsModels) this.b.a(reader);
                    break;
                case 1:
                    remoteAllResultsAssociationModels = (RemoteAllResultsAssociationModels) this.c.a(reader);
                    break;
                case 2:
                    list = (List) this.d.a(reader);
                    break;
                case 3:
                    pagingInfo = (PagingInfo) this.e.a(reader);
                    z = true;
                    break;
                case 4:
                    list2 = (List) this.f.a(reader);
                    z2 = true;
                    break;
                case 5:
                    modelError = (ModelError) this.g.a(reader);
                    z3 = true;
                    break;
            }
        }
        reader.i();
        SearchAllResultsResponse searchAllResultsResponse = new SearchAllResultsResponse(remoteAllResultsModels, remoteAllResultsAssociationModels, list);
        if (z) {
            searchAllResultsResponse.a = pagingInfo;
        }
        if (z2) {
            searchAllResultsResponse.b = list2;
        }
        if (z3) {
            searchAllResultsResponse.c = modelError;
        }
        return searchAllResultsResponse;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SearchAllResultsResponse searchAllResultsResponse = (SearchAllResultsResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (searchAllResultsResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("models");
        this.b.g(writer, searchAllResultsResponse.d);
        writer.l("associations");
        this.c.g(writer, searchAllResultsResponse.e);
        writer.l("shelfRanking");
        this.d.g(writer, searchAllResultsResponse.f);
        writer.l("paging");
        this.e.g(writer, searchAllResultsResponse.a);
        writer.l("validationErrors");
        this.f.g(writer, searchAllResultsResponse.b);
        writer.l("error");
        this.g.g(writer, searchAllResultsResponse.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(46, "GeneratedJsonAdapter(SearchAllResultsResponse)", "toString(...)");
    }
}
