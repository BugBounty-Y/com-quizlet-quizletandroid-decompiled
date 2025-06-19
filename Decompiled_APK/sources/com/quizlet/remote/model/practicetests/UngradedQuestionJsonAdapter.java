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
public final class UngradedQuestionJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;

    public UngradedQuestionJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("questionUuid", "questionIndex", "questionFormat", "answer", "submittedAnswer", "excluded");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "questionUuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, "questionIndex");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, String.class), m, "answer");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(H.f(List.class, String.class), m, "submittedAnswer");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(Boolean.TYPE, m, "excluded");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Integer num = null;
        Boolean bool = null;
        String str = null;
        String str2 = null;
        List list = null;
        List list2 = null;
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
                        throw com.squareup.moshi.internal.b.k("questionUuid", "questionUuid", reader);
                    }
                    break;
                case 1:
                    num = (Integer) this.c.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("questionIndex", "questionIndex", reader);
                    }
                    break;
                case 2:
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("questionFormat", "questionFormat", reader);
                    }
                    break;
                case 3:
                    list = (List) this.d.a(reader);
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.k("answer", "answer", reader);
                    }
                    break;
                case 4:
                    list2 = (List) this.e.a(reader);
                    break;
                case 5:
                    bool = (Boolean) this.f.a(reader);
                    if (bool == null) {
                        throw com.squareup.moshi.internal.b.k("excluded", "excluded", reader);
                    }
                    break;
            }
        }
        reader.i();
        Boolean bool2 = bool;
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("questionUuid", "questionUuid", reader);
        }
        if (num == null) {
            throw com.squareup.moshi.internal.b.e("questionIndex", "questionIndex", reader);
        }
        int iIntValue = num.intValue();
        if (str2 == null) {
            throw com.squareup.moshi.internal.b.e("questionFormat", "questionFormat", reader);
        }
        if (list == null) {
            throw com.squareup.moshi.internal.b.e("answer", "answer", reader);
        }
        if (bool2 != null) {
            return new UngradedQuestion(str, iIntValue, str2, list, list2, bool2.booleanValue());
        }
        throw com.squareup.moshi.internal.b.e("excluded", "excluded", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        UngradedQuestion ungradedQuestion = (UngradedQuestion) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (ungradedQuestion == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("questionUuid");
        l lVar = this.b;
        lVar.g(writer, ungradedQuestion.a);
        writer.l("questionIndex");
        this.c.g(writer, Integer.valueOf(ungradedQuestion.b));
        writer.l("questionFormat");
        lVar.g(writer, ungradedQuestion.c);
        writer.l("answer");
        this.d.g(writer, ungradedQuestion.d);
        writer.l("submittedAnswer");
        this.e.g(writer, ungradedQuestion.e);
        writer.l("excluded");
        this.f.g(writer, Boolean.valueOf(ungradedQuestion.f));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(38, "GeneratedJsonAdapter(UngradedQuestion)", "toString(...)");
    }
}
