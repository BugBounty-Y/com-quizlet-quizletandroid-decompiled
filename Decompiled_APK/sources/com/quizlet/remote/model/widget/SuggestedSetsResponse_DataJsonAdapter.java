package com.quizlet.remote.model.widget;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.widget.SuggestedSetsResponse;
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
public final class SuggestedSetsResponse_DataJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public SuggestedSetsResponse_DataJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("streakData", "setData");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(SuggestedSetsResponse.StreakData.class, m, "streakData");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, SuggestedSetsResponse.SetData.class), m, "setData");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        SuggestedSetsResponse.StreakData streakData = null;
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                streakData = (SuggestedSetsResponse.StreakData) this.b.a(reader);
                if (streakData == null) {
                    throw com.squareup.moshi.internal.b.k("streakData", "streakData", reader);
                }
            } else if (iK0 == 1 && (list = (List) this.c.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("setData", "setData", reader);
            }
        }
        reader.i();
        if (streakData == null) {
            throw com.squareup.moshi.internal.b.e("streakData", "streakData", reader);
        }
        if (list != null) {
            return new SuggestedSetsResponse.Data(streakData, list);
        }
        throw com.squareup.moshi.internal.b.e("setData", "setData", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SuggestedSetsResponse.Data data = (SuggestedSetsResponse.Data) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (data == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("streakData");
        this.b.g(writer, data.a);
        writer.l("setData");
        this.c.g(writer, data.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(48, "GeneratedJsonAdapter(SuggestedSetsResponse.Data)", "toString(...)");
    }
}
