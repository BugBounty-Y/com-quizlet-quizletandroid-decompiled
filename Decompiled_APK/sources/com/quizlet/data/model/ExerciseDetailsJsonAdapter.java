package com.quizlet.data.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ExerciseDetailsJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public final com.squareup.moshi.l f;
    public final com.squareup.moshi.l g;

    public ExerciseDetailsJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "mediaExerciseId", "exercise", "chapterName", "groupName", "sectionName", "chapterTitle", "sectionTitle", "pageNumber", "textbook", "solutions", "nextExercises", "previousExercises", "webUrl");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(String.class, m, "mediaExerciseId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(String.class, m, "groupName");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(Textbook.class, m, "textbook");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        com.squareup.moshi.l lVarA5 = moshi.a(com.squareup.moshi.H.f(List.class, Solution.class), m, "solutions");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        com.squareup.moshi.l lVarA6 = moshi.a(com.squareup.moshi.H.f(List.class, Exercise.class), m, "nextExercises");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        String str5 = null;
        String str6 = null;
        String str7 = null;
        String str8 = null;
        Textbook textbook = null;
        List list = null;
        List list2 = null;
        List list3 = null;
        String str9 = null;
        while (true) {
            Long l2 = l;
            String str10 = str;
            String str11 = str2;
            String str12 = str3;
            String str13 = str4;
            if (!reader.l()) {
                String str14 = str5;
                String str15 = str6;
                String str16 = str7;
                reader.i();
                if (l2 == null) {
                    throw com.squareup.moshi.internal.b.e("id", "id", reader);
                }
                long jLongValue = l2.longValue();
                if (str10 == null) {
                    throw com.squareup.moshi.internal.b.e("mediaExerciseId", "mediaExerciseId", reader);
                }
                if (str11 == null) {
                    throw com.squareup.moshi.internal.b.e("exercise", "exercise", reader);
                }
                if (str12 == null) {
                    throw com.squareup.moshi.internal.b.e("chapterName", "chapterName", reader);
                }
                if (textbook == null) {
                    throw com.squareup.moshi.internal.b.e("textbook", "textbook", reader);
                }
                if (list == null) {
                    throw com.squareup.moshi.internal.b.e("solutions", "solutions", reader);
                }
                if (list2 == null) {
                    throw com.squareup.moshi.internal.b.e("nextExercises", "nextExercises", reader);
                }
                if (list3 != null) {
                    return new ExerciseDetails(jLongValue, str10, str11, str12, str13, str14, str15, str16, str8, textbook, list, list2, list3, str9);
                }
                throw com.squareup.moshi.internal.b.e("previousExercises", "previousExercises", reader);
            }
            String str17 = str5;
            int iK0 = reader.k0(this.a);
            com.squareup.moshi.l lVar = this.g;
            String str18 = str6;
            com.squareup.moshi.l lVar2 = this.c;
            String str19 = str7;
            com.squareup.moshi.l lVar3 = this.d;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    l = l2;
                    str5 = str17;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str6 = str18;
                    str7 = str19;
                case 0:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    str5 = str17;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str6 = str18;
                    str7 = str19;
                case 1:
                    str = (String) lVar2.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("mediaExerciseId", "mediaExerciseId", reader);
                    }
                    l = l2;
                    str5 = str17;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str6 = str18;
                    str7 = str19;
                case 2:
                    str2 = (String) lVar2.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("exercise", "exercise", reader);
                    }
                    l = l2;
                    str5 = str17;
                    str = str10;
                    str3 = str12;
                    str4 = str13;
                    str6 = str18;
                    str7 = str19;
                case 3:
                    str3 = (String) lVar2.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("chapterName", "chapterName", reader);
                    }
                    l = l2;
                    str5 = str17;
                    str = str10;
                    str2 = str11;
                    str4 = str13;
                    str6 = str18;
                    str7 = str19;
                case 4:
                    str4 = (String) lVar3.a(reader);
                    l = l2;
                    str5 = str17;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str6 = str18;
                    str7 = str19;
                case 5:
                    str5 = (String) lVar3.a(reader);
                    l = l2;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str6 = str18;
                    str7 = str19;
                case 6:
                    str6 = (String) lVar3.a(reader);
                    l = l2;
                    str5 = str17;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str7 = str19;
                case 7:
                    str7 = (String) lVar3.a(reader);
                    l = l2;
                    str5 = str17;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str6 = str18;
                case 8:
                    str8 = (String) lVar3.a(reader);
                    l = l2;
                    str5 = str17;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str6 = str18;
                    str7 = str19;
                case 9:
                    textbook = (Textbook) this.e.a(reader);
                    if (textbook == null) {
                        throw com.squareup.moshi.internal.b.k("textbook", "textbook", reader);
                    }
                    l = l2;
                    str5 = str17;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str6 = str18;
                    str7 = str19;
                case 10:
                    list = (List) this.f.a(reader);
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.k("solutions", "solutions", reader);
                    }
                    l = l2;
                    str5 = str17;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str6 = str18;
                    str7 = str19;
                case 11:
                    list2 = (List) lVar.a(reader);
                    if (list2 == null) {
                        throw com.squareup.moshi.internal.b.k("nextExercises", "nextExercises", reader);
                    }
                    l = l2;
                    str5 = str17;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str6 = str18;
                    str7 = str19;
                case 12:
                    list3 = (List) lVar.a(reader);
                    if (list3 == null) {
                        throw com.squareup.moshi.internal.b.k("previousExercises", "previousExercises", reader);
                    }
                    l = l2;
                    str5 = str17;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str6 = str18;
                    str7 = str19;
                case 13:
                    str9 = (String) lVar3.a(reader);
                    l = l2;
                    str5 = str17;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str6 = str18;
                    str7 = str19;
                default:
                    l = l2;
                    str5 = str17;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str6 = str18;
                    str7 = str19;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        ExerciseDetails exerciseDetails = (ExerciseDetails) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (exerciseDetails == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(exerciseDetails.a));
        writer.l("mediaExerciseId");
        com.squareup.moshi.l lVar = this.c;
        lVar.g(writer, exerciseDetails.b);
        writer.l("exercise");
        lVar.g(writer, exerciseDetails.c);
        writer.l("chapterName");
        lVar.g(writer, exerciseDetails.d);
        writer.l("groupName");
        com.squareup.moshi.l lVar2 = this.d;
        lVar2.g(writer, exerciseDetails.e);
        writer.l("sectionName");
        lVar2.g(writer, exerciseDetails.f);
        writer.l("chapterTitle");
        lVar2.g(writer, exerciseDetails.g);
        writer.l("sectionTitle");
        lVar2.g(writer, exerciseDetails.h);
        writer.l("pageNumber");
        lVar2.g(writer, exerciseDetails.i);
        writer.l("textbook");
        this.e.g(writer, exerciseDetails.j);
        writer.l("solutions");
        this.f.g(writer, exerciseDetails.k);
        writer.l("nextExercises");
        com.squareup.moshi.l lVar3 = this.g;
        lVar3.g(writer, exerciseDetails.l);
        writer.l("previousExercises");
        lVar3.g(writer, exerciseDetails.m);
        writer.l("webUrl");
        lVar2.g(writer, exerciseDetails.n);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(37, "GeneratedJsonAdapter(ExerciseDetails)", "toString(...)");
    }
}
