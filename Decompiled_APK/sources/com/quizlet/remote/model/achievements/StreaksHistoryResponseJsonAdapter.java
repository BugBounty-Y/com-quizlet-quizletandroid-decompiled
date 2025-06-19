package com.quizlet.remote.model.achievements;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.achievements.StreaksHistoryResponse;
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
public final class StreaksHistoryResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;

    public StreaksHistoryResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("data", "paging", "validationErrors", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(StreaksHistoryResponse.HistoryDataResponse.class, m, "data");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(PagingInfo.class, m, "pagingInfo");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, ValidationError.class), m, "validationErrors");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(ModelError.class, m, "error");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        StreaksHistoryResponse.HistoryDataResponse historyDataResponse = null;
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
                historyDataResponse = (StreaksHistoryResponse.HistoryDataResponse) this.b.a(reader);
                if (historyDataResponse == null) {
                    throw com.squareup.moshi.internal.b.k("data_", "data", reader);
                }
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
        if (historyDataResponse == null) {
            throw com.squareup.moshi.internal.b.e("data_", "data", reader);
        }
        StreaksHistoryResponse streaksHistoryResponse = new StreaksHistoryResponse(historyDataResponse);
        if (z) {
            streaksHistoryResponse.a = pagingInfo;
        }
        if (z2) {
            streaksHistoryResponse.b = list;
        }
        if (z3) {
            streaksHistoryResponse.c = modelError;
        }
        return streaksHistoryResponse;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        StreaksHistoryResponse streaksHistoryResponse = (StreaksHistoryResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (streaksHistoryResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("data");
        this.b.g(writer, streaksHistoryResponse.d);
        writer.l("paging");
        this.c.g(writer, streaksHistoryResponse.a);
        writer.l("validationErrors");
        this.d.g(writer, streaksHistoryResponse.b);
        writer.l("error");
        this.e.g(writer, streaksHistoryResponse.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(44, "GeneratedJsonAdapter(StreaksHistoryResponse)", "toString(...)");
    }
}
