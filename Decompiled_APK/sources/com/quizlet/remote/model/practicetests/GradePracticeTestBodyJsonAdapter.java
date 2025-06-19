package com.quizlet.remote.model.practicetests;

import com.quizlet.data.model.AbstractC4178x;
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
public final class GradePracticeTestBodyJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;

    public GradePracticeTestBodyJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("questionBankUuid", "practiceTestSessionId", "ungradedQuestions", "testStartedAt", "testSubmittedAt", "testCompletionTimeSeconds", "practiceTestMetadata");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "questionBankUuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, UngradedQuestion.class), m, "ungradedQuestions");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Long.TYPE, m, "testCompletionTimeSeconds");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(PracticeTestMetadata.class, m, "practiceTestMetadata");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        String str = null;
        String str2 = null;
        List list = null;
        String str3 = null;
        String str4 = null;
        PracticeTestMetadata practiceTestMetadata = null;
        while (true) {
            Long l2 = l;
            if (!reader.l()) {
                reader.i();
                if (str == null) {
                    throw com.squareup.moshi.internal.b.e("questionBankUuid", "questionBankUuid", reader);
                }
                if (str2 == null) {
                    throw com.squareup.moshi.internal.b.e("practiceTestSessionId", "practiceTestSessionId", reader);
                }
                if (list == null) {
                    throw com.squareup.moshi.internal.b.e("ungradedQuestions", "ungradedQuestions", reader);
                }
                if (str3 == null) {
                    throw com.squareup.moshi.internal.b.e("testStartedAt", "testStartedAt", reader);
                }
                if (str4 == null) {
                    throw com.squareup.moshi.internal.b.e("testSubmittedAt", "testSubmittedAt", reader);
                }
                if (l2 == null) {
                    throw com.squareup.moshi.internal.b.e("testCompletionTimeSeconds", "testCompletionTimeSeconds", reader);
                }
                long jLongValue = l2.longValue();
                if (practiceTestMetadata != null) {
                    return new GradePracticeTestBody(str, str2, list, str3, str4, jLongValue, practiceTestMetadata);
                }
                throw com.squareup.moshi.internal.b.e("practiceTestMetadata", "practiceTestMetadata", reader);
            }
            int iK0 = reader.k0(this.a);
            l lVar = this.b;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("questionBankUuid", "questionBankUuid", reader);
                    }
                    break;
                case 1:
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("practiceTestSessionId", "practiceTestSessionId", reader);
                    }
                    break;
                case 2:
                    list = (List) this.c.a(reader);
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.k("ungradedQuestions", "ungradedQuestions", reader);
                    }
                    break;
                case 3:
                    str3 = (String) lVar.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("testStartedAt", "testStartedAt", reader);
                    }
                    break;
                case 4:
                    str4 = (String) lVar.a(reader);
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.k("testSubmittedAt", "testSubmittedAt", reader);
                    }
                    break;
                case 5:
                    l = (Long) this.d.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("testCompletionTimeSeconds", "testCompletionTimeSeconds", reader);
                    }
                    continue;
                case 6:
                    practiceTestMetadata = (PracticeTestMetadata) this.e.a(reader);
                    if (practiceTestMetadata == null) {
                        throw com.squareup.moshi.internal.b.k("practiceTestMetadata", "practiceTestMetadata", reader);
                    }
                    break;
            }
            l = l2;
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        GradePracticeTestBody gradePracticeTestBody = (GradePracticeTestBody) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (gradePracticeTestBody == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("questionBankUuid");
        l lVar = this.b;
        lVar.g(writer, gradePracticeTestBody.a);
        writer.l("practiceTestSessionId");
        lVar.g(writer, gradePracticeTestBody.b);
        writer.l("ungradedQuestions");
        this.c.g(writer, gradePracticeTestBody.c);
        writer.l("testStartedAt");
        lVar.g(writer, gradePracticeTestBody.d);
        writer.l("testSubmittedAt");
        lVar.g(writer, gradePracticeTestBody.e);
        writer.l("testCompletionTimeSeconds");
        this.d.g(writer, Long.valueOf(gradePracticeTestBody.f));
        writer.l("practiceTestMetadata");
        this.e.g(writer, gradePracticeTestBody.g);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(43, "GeneratedJsonAdapter(GradePracticeTestBody)", "toString(...)");
    }
}
