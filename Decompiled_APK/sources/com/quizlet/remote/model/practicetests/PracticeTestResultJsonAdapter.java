package com.quizlet.remote.model.practicetests;

import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestResultJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public final l g;

    public PracticeTestResultJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("gradedQuestions", "durationSeconds", "round", "questionBankUuid", "configuration", "practiceTestMetadata", "questionCounts");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, PracticeTestGradedQuestionResponse.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "gradedQuestions");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, "durationSeconds");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(String.class, m, "questionBankUuid");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(PracticeTestConfigurationResponse.class, m, "configuration");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(RemotePracticeTestSetId.class, m, "practiceTestMetadata");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(H.f(Map.class, String.class, Integer.class), m, "questionCounts");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Integer num = null;
        Integer num2 = null;
        List list = null;
        String str = null;
        PracticeTestConfigurationResponse practiceTestConfigurationResponse = null;
        RemotePracticeTestSetId remotePracticeTestSetId = null;
        Map map = null;
        while (true) {
            Integer num3 = num;
            if (!reader.l()) {
                Integer num4 = num2;
                reader.i();
                if (list == null) {
                    throw com.squareup.moshi.internal.b.e("gradedQuestions", "gradedQuestions", reader);
                }
                if (num3 == null) {
                    throw com.squareup.moshi.internal.b.e("durationSeconds", "durationSeconds", reader);
                }
                int iIntValue = num3.intValue();
                if (num4 == null) {
                    throw com.squareup.moshi.internal.b.e("round", "round", reader);
                }
                int iIntValue2 = num4.intValue();
                if (str == null) {
                    throw com.squareup.moshi.internal.b.e("questionBankUuid", "questionBankUuid", reader);
                }
                if (practiceTestConfigurationResponse == null) {
                    throw com.squareup.moshi.internal.b.e("configuration", "configuration", reader);
                }
                if (remotePracticeTestSetId == null) {
                    throw com.squareup.moshi.internal.b.e("practiceTestMetadata", "practiceTestMetadata", reader);
                }
                if (map != null) {
                    return new PracticeTestResult(list, iIntValue, iIntValue2, str, practiceTestConfigurationResponse, remotePracticeTestSetId, map);
                }
                throw com.squareup.moshi.internal.b.e("questionCounts", "questionCounts", reader);
            }
            int iK0 = reader.k0(this.a);
            Integer num5 = num2;
            l lVar = this.c;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    num = num3;
                    num2 = num5;
                case 0:
                    list = (List) this.b.a(reader);
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.k("gradedQuestions", "gradedQuestions", reader);
                    }
                    num = num3;
                    num2 = num5;
                case 1:
                    num = (Integer) lVar.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("durationSeconds", "durationSeconds", reader);
                    }
                    num2 = num5;
                case 2:
                    num2 = (Integer) lVar.a(reader);
                    if (num2 == null) {
                        throw com.squareup.moshi.internal.b.k("round", "round", reader);
                    }
                    num = num3;
                case 3:
                    str = (String) this.d.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("questionBankUuid", "questionBankUuid", reader);
                    }
                    num = num3;
                    num2 = num5;
                case 4:
                    practiceTestConfigurationResponse = (PracticeTestConfigurationResponse) this.e.a(reader);
                    if (practiceTestConfigurationResponse == null) {
                        throw com.squareup.moshi.internal.b.k("configuration", "configuration", reader);
                    }
                    num = num3;
                    num2 = num5;
                case 5:
                    remotePracticeTestSetId = (RemotePracticeTestSetId) this.f.a(reader);
                    if (remotePracticeTestSetId == null) {
                        throw com.squareup.moshi.internal.b.k("practiceTestMetadata", "practiceTestMetadata", reader);
                    }
                    num = num3;
                    num2 = num5;
                case 6:
                    map = (Map) this.g.a(reader);
                    if (map == null) {
                        throw com.squareup.moshi.internal.b.k("questionCounts", "questionCounts", reader);
                    }
                    num = num3;
                    num2 = num5;
                default:
                    num = num3;
                    num2 = num5;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        PracticeTestResult practiceTestResult = (PracticeTestResult) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (practiceTestResult == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("gradedQuestions");
        this.b.g(writer, practiceTestResult.a);
        writer.l("durationSeconds");
        Integer numValueOf = Integer.valueOf(practiceTestResult.b);
        l lVar = this.c;
        lVar.g(writer, numValueOf);
        writer.l("round");
        AbstractC4178x.p(practiceTestResult.c, lVar, writer, "questionBankUuid");
        this.d.g(writer, practiceTestResult.d);
        writer.l("configuration");
        this.e.g(writer, practiceTestResult.e);
        writer.l("practiceTestMetadata");
        this.f.g(writer, practiceTestResult.f);
        writer.l("questionCounts");
        this.g.g(writer, practiceTestResult.g);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(40, "GeneratedJsonAdapter(PracticeTestResult)", "toString(...)");
    }
}
