package com.quizlet.remote.model.practicetests;

import com.quizlet.data.model.AbstractC4178x;
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
public final class PracticeTestSummaryResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;

    public PracticeTestSummaryResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("practiceTestUuid", "startedAt", "durationSeconds", "correctCount", "totalCount");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "practiceTestUuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Long.TYPE, m, "durationSeconds");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Integer.TYPE, m, "correctCount");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Integer num = null;
        String str = null;
        String str2 = null;
        Integer num2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("practiceTestUuid", "practiceTestUuid", reader);
                    }
                } else if (iK0 == 1) {
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("startedAt", "startedAt", reader);
                    }
                } else if (iK0 != 2) {
                    l lVar2 = this.d;
                    if (iK0 == 3) {
                        num = (Integer) lVar2.a(reader);
                        if (num == null) {
                            throw com.squareup.moshi.internal.b.k("correctCount", "correctCount", reader);
                        }
                    } else if (iK0 == 4 && (num2 = (Integer) lVar2.a(reader)) == null) {
                        throw com.squareup.moshi.internal.b.k("totalCount", "totalCount", reader);
                    }
                } else {
                    l = (Long) this.c.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("durationSeconds", "durationSeconds", reader);
                    }
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        Integer num3 = num;
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("practiceTestUuid", "practiceTestUuid", reader);
        }
        if (str2 == null) {
            throw com.squareup.moshi.internal.b.e("startedAt", "startedAt", reader);
        }
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("durationSeconds", "durationSeconds", reader);
        }
        long jLongValue = l.longValue();
        if (num3 == null) {
            throw com.squareup.moshi.internal.b.e("correctCount", "correctCount", reader);
        }
        int iIntValue = num3.intValue();
        if (num2 != null) {
            return new PracticeTestSummaryResponse(str, str2, jLongValue, iIntValue, num2.intValue());
        }
        throw com.squareup.moshi.internal.b.e("totalCount", "totalCount", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        PracticeTestSummaryResponse practiceTestSummaryResponse = (PracticeTestSummaryResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (practiceTestSummaryResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("practiceTestUuid");
        String str = practiceTestSummaryResponse.a;
        l lVar = this.b;
        lVar.g(writer, str);
        writer.l("startedAt");
        lVar.g(writer, practiceTestSummaryResponse.b);
        writer.l("durationSeconds");
        this.c.g(writer, Long.valueOf(practiceTestSummaryResponse.c));
        writer.l("correctCount");
        Integer numValueOf = Integer.valueOf(practiceTestSummaryResponse.d);
        l lVar2 = this.d;
        lVar2.g(writer, numValueOf);
        writer.l("totalCount");
        lVar2.g(writer, Integer.valueOf(practiceTestSummaryResponse.e));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(49, "GeneratedJsonAdapter(PracticeTestSummaryResponse)", "toString(...)");
    }
}
