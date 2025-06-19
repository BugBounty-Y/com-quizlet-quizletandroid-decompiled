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
public final class PracticeTestBodyJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;

    public PracticeTestBodyJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("questionBankUuid", "round", "configuration", "entryPoint", "questionBankMetadata", "questionCompatibility");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "questionBankUuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, "round");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(PracticeTestConfiguration.class, m, "configuration");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(QuestionBankMetadata.class, m, "questionBankMetadata");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(QuestionCompatibility.class, m, "questionCompatibility");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Integer num = null;
        String str = null;
        PracticeTestConfiguration practiceTestConfiguration = null;
        String str2 = null;
        QuestionBankMetadata questionBankMetadata = null;
        QuestionCompatibility questionCompatibility = null;
        while (reader.l()) {
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
                    num = (Integer) this.c.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("round", "round", reader);
                    }
                    break;
                case 2:
                    practiceTestConfiguration = (PracticeTestConfiguration) this.d.a(reader);
                    if (practiceTestConfiguration == null) {
                        throw com.squareup.moshi.internal.b.k("configuration", "configuration", reader);
                    }
                    break;
                case 3:
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("entryPoint", "entryPoint", reader);
                    }
                    break;
                case 4:
                    questionBankMetadata = (QuestionBankMetadata) this.e.a(reader);
                    if (questionBankMetadata == null) {
                        throw com.squareup.moshi.internal.b.k("questionBankMetadata", "questionBankMetadata", reader);
                    }
                    break;
                case 5:
                    questionCompatibility = (QuestionCompatibility) this.f.a(reader);
                    if (questionCompatibility == null) {
                        throw com.squareup.moshi.internal.b.k("questionCompatibility", "questionCompatibility", reader);
                    }
                    break;
            }
        }
        reader.i();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("questionBankUuid", "questionBankUuid", reader);
        }
        if (num == null) {
            throw com.squareup.moshi.internal.b.e("round", "round", reader);
        }
        int iIntValue = num.intValue();
        if (practiceTestConfiguration == null) {
            throw com.squareup.moshi.internal.b.e("configuration", "configuration", reader);
        }
        if (str2 == null) {
            throw com.squareup.moshi.internal.b.e("entryPoint", "entryPoint", reader);
        }
        if (questionBankMetadata == null) {
            throw com.squareup.moshi.internal.b.e("questionBankMetadata", "questionBankMetadata", reader);
        }
        if (questionCompatibility != null) {
            return new PracticeTestBody(str, iIntValue, practiceTestConfiguration, str2, questionBankMetadata, questionCompatibility);
        }
        throw com.squareup.moshi.internal.b.e("questionCompatibility", "questionCompatibility", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        PracticeTestBody practiceTestBody = (PracticeTestBody) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (practiceTestBody == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("questionBankUuid");
        l lVar = this.b;
        lVar.g(writer, practiceTestBody.a);
        writer.l("round");
        this.c.g(writer, Integer.valueOf(practiceTestBody.b));
        writer.l("configuration");
        this.d.g(writer, practiceTestBody.c);
        writer.l("entryPoint");
        lVar.g(writer, practiceTestBody.d);
        writer.l("questionBankMetadata");
        this.e.g(writer, practiceTestBody.e);
        writer.l("questionCompatibility");
        this.f.g(writer, practiceTestBody.f);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(38, "GeneratedJsonAdapter(PracticeTestBody)", "toString(...)");
    }
}
