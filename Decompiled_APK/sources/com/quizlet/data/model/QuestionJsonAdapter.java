package com.quizlet.data.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class QuestionJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public final com.squareup.moshi.l f;
    public final com.squareup.moshi.l g;
    public final com.squareup.moshi.l h;

    public QuestionJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "slug", "mediaExerciseId", "questionUuid", "subjects", "prompt", "answersCount", "webUrl", "solutions");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(String.class, m, "slug");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(com.squareup.moshi.H.f(List.class, com.quizlet.generated.enums.D.class), m, "subjects");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(QuestionPrompt.class, m, "prompt");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        com.squareup.moshi.l lVarA5 = moshi.a(Integer.class, m, "answersCount");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        com.squareup.moshi.l lVarA6 = moshi.a(String.class, m, "webUrl");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
        com.squareup.moshi.l lVarA7 = moshi.a(com.squareup.moshi.H.f(List.class, Solution.class), m, "solutions");
        Intrinsics.checkNotNullExpressionValue(lVarA7, "adapter(...)");
        this.h = lVarA7;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        List list = null;
        QuestionPrompt questionPrompt = null;
        Integer num = null;
        String str4 = null;
        List list2 = null;
        while (true) {
            Long l2 = l;
            String str5 = str;
            if (!reader.l()) {
                String str6 = str2;
                reader.i();
                if (l2 == null) {
                    throw com.squareup.moshi.internal.b.e("id", "id", reader);
                }
                long jLongValue = l2.longValue();
                if (str5 == null) {
                    throw com.squareup.moshi.internal.b.e("slug", "slug", reader);
                }
                if (str6 == null) {
                    throw com.squareup.moshi.internal.b.e("mediaExerciseId", "mediaExerciseId", reader);
                }
                if (str3 == null) {
                    throw com.squareup.moshi.internal.b.e("questionUuid", "questionUuid", reader);
                }
                if (list == null) {
                    throw com.squareup.moshi.internal.b.e("subjects", "subjects", reader);
                }
                if (questionPrompt == null) {
                    throw com.squareup.moshi.internal.b.e("prompt", "prompt", reader);
                }
                if (list2 != null) {
                    return new Question(jLongValue, str5, str6, str3, list, questionPrompt, num, str4, list2);
                }
                throw com.squareup.moshi.internal.b.e("solutions", "solutions", reader);
            }
            String str7 = str2;
            int iK0 = reader.k0(this.a);
            com.squareup.moshi.l lVar = this.c;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    l = l2;
                    str2 = str7;
                    str = str5;
                case 0:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    str2 = str7;
                    str = str5;
                case 1:
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("slug", "slug", reader);
                    }
                    l = l2;
                    str2 = str7;
                case 2:
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("mediaExerciseId", "mediaExerciseId", reader);
                    }
                    l = l2;
                    str = str5;
                case 3:
                    str3 = (String) lVar.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("questionUuid", "questionUuid", reader);
                    }
                    l = l2;
                    str2 = str7;
                    str = str5;
                case 4:
                    list = (List) this.d.a(reader);
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.k("subjects", "subjects", reader);
                    }
                    l = l2;
                    str2 = str7;
                    str = str5;
                case 5:
                    questionPrompt = (QuestionPrompt) this.e.a(reader);
                    if (questionPrompt == null) {
                        throw com.squareup.moshi.internal.b.k("prompt", "prompt", reader);
                    }
                    l = l2;
                    str2 = str7;
                    str = str5;
                case 6:
                    num = (Integer) this.f.a(reader);
                    l = l2;
                    str2 = str7;
                    str = str5;
                case 7:
                    str4 = (String) this.g.a(reader);
                    l = l2;
                    str2 = str7;
                    str = str5;
                case 8:
                    list2 = (List) this.h.a(reader);
                    if (list2 == null) {
                        throw com.squareup.moshi.internal.b.k("solutions", "solutions", reader);
                    }
                    l = l2;
                    str2 = str7;
                    str = str5;
                default:
                    l = l2;
                    str2 = str7;
                    str = str5;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        Question question = (Question) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (question == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(question.a));
        writer.l("slug");
        com.squareup.moshi.l lVar = this.c;
        lVar.g(writer, question.b);
        writer.l("mediaExerciseId");
        lVar.g(writer, question.c);
        writer.l("questionUuid");
        lVar.g(writer, question.d);
        writer.l("subjects");
        this.d.g(writer, question.e);
        writer.l("prompt");
        this.e.g(writer, question.f);
        writer.l("answersCount");
        this.f.g(writer, question.g);
        writer.l("webUrl");
        this.g.g(writer, question.h);
        writer.l("solutions");
        this.h.g(writer, question.i);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(30, "GeneratedJsonAdapter(Question)", "toString(...)");
    }
}
