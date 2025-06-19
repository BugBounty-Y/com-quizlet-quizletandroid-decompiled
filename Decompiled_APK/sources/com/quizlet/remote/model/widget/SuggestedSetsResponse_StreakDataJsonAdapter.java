package com.quizlet.remote.model.widget;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.widget.SuggestedSetsResponse;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SuggestedSetsResponse_StreakDataJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;

    public SuggestedSetsResponse_StreakDataJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("length", "progressType", "lastHistoryDate");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Integer.class, m, "length");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "progressType");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Long.class, m, "lastHistoryDate");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Integer num = null;
        String str = null;
        Long l = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                num = (Integer) this.b.a(reader);
            } else if (iK0 == 1) {
                str = (String) this.c.a(reader);
            } else if (iK0 == 2) {
                l = (Long) this.d.a(reader);
            }
        }
        reader.i();
        return new SuggestedSetsResponse.StreakData(num, str, l);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SuggestedSetsResponse.StreakData streakData = (SuggestedSetsResponse.StreakData) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (streakData == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("length");
        this.b.g(writer, streakData.a);
        writer.l("progressType");
        this.c.g(writer, streakData.b);
        writer.l("lastHistoryDate");
        this.d.g(writer, streakData.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(54, "GeneratedJsonAdapter(SuggestedSetsResponse.StreakData)", "toString(...)");
    }
}
