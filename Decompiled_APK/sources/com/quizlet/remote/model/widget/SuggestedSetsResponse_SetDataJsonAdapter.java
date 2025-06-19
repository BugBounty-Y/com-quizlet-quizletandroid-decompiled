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
public final class SuggestedSetsResponse_SetDataJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;

    public SuggestedSetsResponse_SetDataJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("id", "title", "count", "itemsKnown", "itemsStillLearning", "itemsRemaining", "memoryScores");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "title");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Integer.TYPE, m, "count");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(H.f(List.class, SuggestedSetsResponse.MemoryScore.class), m, "memoryScores");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Integer num = null;
        Integer num2 = null;
        Integer num3 = null;
        String str = null;
        Integer num4 = null;
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            Long l2 = l;
            l lVar = this.d;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    continue;
                case 1:
                    str = (String) this.c.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("title", "title", reader);
                    }
                    break;
                case 2:
                    num = (Integer) lVar.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("count", "count", reader);
                    }
                    break;
                case 3:
                    num2 = (Integer) lVar.a(reader);
                    if (num2 == null) {
                        throw com.squareup.moshi.internal.b.k("itemsKnown", "itemsKnown", reader);
                    }
                    break;
                case 4:
                    num3 = (Integer) lVar.a(reader);
                    if (num3 == null) {
                        throw com.squareup.moshi.internal.b.k("itemsStillLearning", "itemsStillLearning", reader);
                    }
                    break;
                case 5:
                    num4 = (Integer) lVar.a(reader);
                    if (num4 == null) {
                        throw com.squareup.moshi.internal.b.k("itemsRemaining", "itemsRemaining", reader);
                    }
                    break;
                case 6:
                    list = (List) this.e.a(reader);
                    break;
            }
            l = l2;
        }
        Long l3 = l;
        reader.i();
        Integer num5 = num;
        if (l3 == null) {
            throw com.squareup.moshi.internal.b.e("id", "id", reader);
        }
        long jLongValue = l3.longValue();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("title", "title", reader);
        }
        if (num5 == null) {
            throw com.squareup.moshi.internal.b.e("count", "count", reader);
        }
        int iIntValue = num5.intValue();
        if (num2 == null) {
            throw com.squareup.moshi.internal.b.e("itemsKnown", "itemsKnown", reader);
        }
        int iIntValue2 = num2.intValue();
        if (num3 == null) {
            throw com.squareup.moshi.internal.b.e("itemsStillLearning", "itemsStillLearning", reader);
        }
        int iIntValue3 = num3.intValue();
        if (num4 != null) {
            return new SuggestedSetsResponse.SetData(jLongValue, str, iIntValue, iIntValue2, iIntValue3, num4.intValue(), list);
        }
        throw com.squareup.moshi.internal.b.e("itemsRemaining", "itemsRemaining", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SuggestedSetsResponse.SetData setData = (SuggestedSetsResponse.SetData) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (setData == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(setData.a));
        writer.l("title");
        this.c.g(writer, setData.b);
        writer.l("count");
        Integer numValueOf = Integer.valueOf(setData.c);
        l lVar = this.d;
        lVar.g(writer, numValueOf);
        writer.l("itemsKnown");
        AbstractC4178x.p(setData.d, lVar, writer, "itemsStillLearning");
        AbstractC4178x.p(setData.e, lVar, writer, "itemsRemaining");
        AbstractC4178x.p(setData.f, lVar, writer, "memoryScores");
        this.e.g(writer, setData.g);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(51, "GeneratedJsonAdapter(SuggestedSetsResponse.SetData)", "toString(...)");
    }
}
