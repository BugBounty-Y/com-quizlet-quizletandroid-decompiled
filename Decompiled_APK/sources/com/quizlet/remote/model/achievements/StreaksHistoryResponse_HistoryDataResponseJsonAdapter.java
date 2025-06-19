package com.quizlet.remote.model.achievements;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.achievements.StreaksHistoryResponse;
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
public final class StreaksHistoryResponse_HistoryDataResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;

    public StreaksHistoryResponse_HistoryDataResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("dates");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(H.f(List.class, Long.class), M.a, "dates");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (list = (List) this.b.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("dates", "dates", reader);
            }
        }
        reader.i();
        if (list != null) {
            return new StreaksHistoryResponse.HistoryDataResponse(list);
        }
        throw com.squareup.moshi.internal.b.e("dates", "dates", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        StreaksHistoryResponse.HistoryDataResponse historyDataResponse = (StreaksHistoryResponse.HistoryDataResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (historyDataResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("dates");
        this.b.g(writer, historyDataResponse.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(64, "GeneratedJsonAdapter(StreaksHistoryResponse.HistoryDataResponse)", "toString(...)");
    }
}
