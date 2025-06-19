package com.quizlet.remote.model.widget;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
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
public final class SuggestedSetsResponse_MemoryScoreJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public SuggestedSetsResponse_MemoryScoreJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("delay", DBSessionFields.Names.SCORE, "label");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Integer.TYPE, m, "delay");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "label");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Integer num = null;
        Integer num2 = null;
        String str = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    num = (Integer) lVar.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("delay", "delay", reader);
                    }
                } else if (iK0 == 1) {
                    num2 = (Integer) lVar.a(reader);
                    if (num2 == null) {
                        throw com.squareup.moshi.internal.b.k(DBSessionFields.Names.SCORE, DBSessionFields.Names.SCORE, reader);
                    }
                } else if (iK0 == 2 && (str = (String) this.c.a(reader)) == null) {
                    throw com.squareup.moshi.internal.b.k("label", "label", reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (num == null) {
            throw com.squareup.moshi.internal.b.e("delay", "delay", reader);
        }
        int iIntValue = num.intValue();
        if (num2 == null) {
            throw com.squareup.moshi.internal.b.e(DBSessionFields.Names.SCORE, DBSessionFields.Names.SCORE, reader);
        }
        int iIntValue2 = num2.intValue();
        if (str != null) {
            return new SuggestedSetsResponse.MemoryScore(iIntValue, iIntValue2, str);
        }
        throw com.squareup.moshi.internal.b.e("label", "label", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SuggestedSetsResponse.MemoryScore memoryScore = (SuggestedSetsResponse.MemoryScore) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (memoryScore == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("delay");
        Integer numValueOf = Integer.valueOf(memoryScore.a);
        l lVar = this.b;
        lVar.g(writer, numValueOf);
        writer.l(DBSessionFields.Names.SCORE);
        AbstractC4178x.p(memoryScore.b, lVar, writer, "label");
        this.c.g(writer, memoryScore.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(55, "GeneratedJsonAdapter(SuggestedSetsResponse.MemoryScore)", "toString(...)");
    }
}
