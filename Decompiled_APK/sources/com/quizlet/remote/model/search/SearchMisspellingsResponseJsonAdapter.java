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
import java.lang.reflect.Constructor;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SearchMisspellingsResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public volatile Constructor g;

    public SearchMisspellingsResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("originalQuery", "correctedQuery", "isQueryCorrected", "misspellingsMessage", "paging", "validationErrors", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "originalQuery");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Boolean.class, m, "isQueryCorrected");
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
    public final Object a(p reader) throws NoSuchMethodException, SecurityException {
        SearchMisspellingsResponse searchMisspellingsResponse;
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        PagingInfo pagingInfo = null;
        String str = null;
        String str2 = null;
        Boolean bool = null;
        String str3 = null;
        boolean z = false;
        boolean z2 = false;
        boolean z3 = false;
        int i = -1;
        List list = null;
        ModelError modelError = null;
        while (reader.l()) {
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    str = (String) this.b.a(reader);
                    i &= -2;
                    break;
                case 1:
                    str2 = (String) this.b.a(reader);
                    i &= -3;
                    break;
                case 2:
                    bool = (Boolean) this.c.a(reader);
                    i &= -5;
                    break;
                case 3:
                    str3 = (String) this.b.a(reader);
                    i &= -9;
                    break;
                case 4:
                    pagingInfo = (PagingInfo) this.d.a(reader);
                    z = true;
                    break;
                case 5:
                    list = (List) this.e.a(reader);
                    z2 = true;
                    break;
                case 6:
                    modelError = (ModelError) this.f.a(reader);
                    z3 = true;
                    break;
            }
        }
        reader.i();
        if (i == -16) {
            searchMisspellingsResponse = new SearchMisspellingsResponse(str, str2, bool, str3);
        } else {
            Constructor declaredConstructor = this.g;
            if (declaredConstructor == null) {
                declaredConstructor = SearchMisspellingsResponse.class.getDeclaredConstructor(String.class, String.class, Boolean.class, String.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
                this.g = declaredConstructor;
                Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
            }
            searchMisspellingsResponse = (SearchMisspellingsResponse) declaredConstructor.newInstance(str, str2, bool, str3, Integer.valueOf(i), null);
        }
        if (z) {
            searchMisspellingsResponse.a = pagingInfo;
        }
        if (z2) {
            searchMisspellingsResponse.b = list;
        }
        if (z3) {
            searchMisspellingsResponse.c = modelError;
        }
        return searchMisspellingsResponse;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SearchMisspellingsResponse searchMisspellingsResponse = (SearchMisspellingsResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (searchMisspellingsResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("originalQuery");
        l lVar = this.b;
        lVar.g(writer, searchMisspellingsResponse.d);
        writer.l("correctedQuery");
        lVar.g(writer, searchMisspellingsResponse.e);
        writer.l("isQueryCorrected");
        this.c.g(writer, searchMisspellingsResponse.f);
        writer.l("misspellingsMessage");
        lVar.g(writer, searchMisspellingsResponse.g);
        writer.l("paging");
        this.d.g(writer, searchMisspellingsResponse.a);
        writer.l("validationErrors");
        this.e.g(writer, searchMisspellingsResponse.b);
        writer.l("error");
        this.f.g(writer, searchMisspellingsResponse.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(48, "GeneratedJsonAdapter(SearchMisspellingsResponse)", "toString(...)");
    }
}
