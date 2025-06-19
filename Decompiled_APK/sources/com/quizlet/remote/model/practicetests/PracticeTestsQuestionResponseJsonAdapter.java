package com.quizlet.remote.model.practicetests;

import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestsQuestionResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public volatile Constructor g;

    public PracticeTestsQuestionResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("questionId", "sourceId", "question", "answer", "source", "answerOptions", "questionFormat", "concepts", "images");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "questionId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, String.class), m, "answer");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(Map.class, String.class, PracticeTestsAnswerOptionResponse.class), m, "answerOptions");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(H.f(List.class, String.class), m, "concepts");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(H.f(List.class, PracticeTestsImageDataResponse.class), m, "images");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        int i;
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        int i2 = -1;
        String str = null;
        String str2 = null;
        String str3 = null;
        List list = null;
        String str4 = null;
        Map map = null;
        String str5 = null;
        List list2 = null;
        List list3 = null;
        while (true) {
            String str6 = str;
            String str7 = str2;
            if (!reader.l()) {
                String str8 = str3;
                reader.i();
                if (i2 == -417) {
                    if (str6 == null) {
                        throw com.squareup.moshi.internal.b.e("questionId", "questionId", reader);
                    }
                    if (str7 == null) {
                        throw com.squareup.moshi.internal.b.e("sourceId", "sourceId", reader);
                    }
                    if (str8 == null) {
                        throw com.squareup.moshi.internal.b.e("question", "question", reader);
                    }
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.e("answer", "answer", reader);
                    }
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.e("source", "source", reader);
                    }
                    if (str5 == null) {
                        throw com.squareup.moshi.internal.b.e("questionFormat", "questionFormat", reader);
                    }
                    List list4 = list3;
                    List list5 = list2;
                    String str9 = str5;
                    return new PracticeTestsQuestionResponse(str6, str7, str8, list, str4, map, str9, list5, list4);
                }
                Constructor declaredConstructor = this.g;
                if (declaredConstructor == null) {
                    i = i2;
                    declaredConstructor = PracticeTestsQuestionResponse.class.getDeclaredConstructor(String.class, String.class, String.class, List.class, String.class, Map.class, String.class, List.class, List.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
                    this.g = declaredConstructor;
                    Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
                } else {
                    i = i2;
                }
                Constructor constructor = declaredConstructor;
                if (str6 == null) {
                    throw com.squareup.moshi.internal.b.e("questionId", "questionId", reader);
                }
                if (str7 == null) {
                    throw com.squareup.moshi.internal.b.e("sourceId", "sourceId", reader);
                }
                if (str8 == null) {
                    throw com.squareup.moshi.internal.b.e("question", "question", reader);
                }
                if (list == null) {
                    throw com.squareup.moshi.internal.b.e("answer", "answer", reader);
                }
                if (str4 == null) {
                    throw com.squareup.moshi.internal.b.e("source", "source", reader);
                }
                if (str5 == null) {
                    throw com.squareup.moshi.internal.b.e("questionFormat", "questionFormat", reader);
                }
                Object objNewInstance = constructor.newInstance(str6, str7, str8, list, str4, map, str5, list2, list3, Integer.valueOf(i), null);
                Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
                return (PracticeTestsQuestionResponse) objNewInstance;
            }
            String str10 = str3;
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    str3 = str10;
                    str = str6;
                    str2 = str7;
                case 0:
                    str = (String) this.b.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("questionId", "questionId", reader);
                    }
                    str3 = str10;
                    str2 = str7;
                case 1:
                    str2 = (String) this.b.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("sourceId", "sourceId", reader);
                    }
                    str3 = str10;
                    str = str6;
                case 2:
                    str3 = (String) this.b.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("question", "question", reader);
                    }
                    str = str6;
                    str2 = str7;
                case 3:
                    list = (List) this.c.a(reader);
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.k("answer", "answer", reader);
                    }
                    str3 = str10;
                    str = str6;
                    str2 = str7;
                case 4:
                    str4 = (String) this.b.a(reader);
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.k("source", "source", reader);
                    }
                    str3 = str10;
                    str = str6;
                    str2 = str7;
                case 5:
                    map = (Map) this.d.a(reader);
                    i2 &= -33;
                    str3 = str10;
                    str = str6;
                    str2 = str7;
                case 6:
                    str5 = (String) this.b.a(reader);
                    if (str5 == null) {
                        throw com.squareup.moshi.internal.b.k("questionFormat", "questionFormat", reader);
                    }
                    str3 = str10;
                    str = str6;
                    str2 = str7;
                case 7:
                    list2 = (List) this.e.a(reader);
                    i2 &= -129;
                    str3 = str10;
                    str = str6;
                    str2 = str7;
                case 8:
                    list3 = (List) this.f.a(reader);
                    i2 &= -257;
                    str3 = str10;
                    str = str6;
                    str2 = str7;
                default:
                    str3 = str10;
                    str = str6;
                    str2 = str7;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        PracticeTestsQuestionResponse practiceTestsQuestionResponse = (PracticeTestsQuestionResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (practiceTestsQuestionResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("questionId");
        l lVar = this.b;
        lVar.g(writer, practiceTestsQuestionResponse.a);
        writer.l("sourceId");
        lVar.g(writer, practiceTestsQuestionResponse.b);
        writer.l("question");
        lVar.g(writer, practiceTestsQuestionResponse.c);
        writer.l("answer");
        this.c.g(writer, practiceTestsQuestionResponse.d);
        writer.l("source");
        lVar.g(writer, practiceTestsQuestionResponse.e);
        writer.l("answerOptions");
        this.d.g(writer, practiceTestsQuestionResponse.f);
        writer.l("questionFormat");
        lVar.g(writer, practiceTestsQuestionResponse.g);
        writer.l("concepts");
        this.e.g(writer, practiceTestsQuestionResponse.h);
        writer.l("images");
        this.f.g(writer, practiceTestsQuestionResponse.i);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(51, "GeneratedJsonAdapter(PracticeTestsQuestionResponse)", "toString(...)");
    }
}
