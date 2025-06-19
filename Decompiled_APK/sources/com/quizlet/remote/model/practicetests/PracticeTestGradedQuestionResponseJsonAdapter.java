package com.quizlet.remote.model.practicetests;

import com.google.android.gms.measurement.internal.Z;
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
public final class PracticeTestGradedQuestionResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public final l g;
    public final l h;
    public volatile Constructor i;

    public PracticeTestGradedQuestionResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("questionUuid", "question", "answer", "answerOptions", "questionFormat", "questionIndex", "userAnswer", "grade", "images", "active", "excluded", "contentFormat", "mediaType");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "questionUuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, String.class), m, "answer");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(Map.class, String.class, PracticeTestsAnswerOptionResponse.class), m, "answerOptions");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(Integer.TYPE, m, "questionIndex");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(H.f(List.class, PracticeTestsImageDataResponse.class), m, "images");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(Boolean.TYPE, m, "active");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
        l lVarA7 = moshi.a(String.class, m, "mediaType");
        Intrinsics.checkNotNullExpressionValue(lVarA7, "adapter(...)");
        this.h = lVarA7;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        int i = -1;
        String str = null;
        String str2 = null;
        List list = null;
        Map map = null;
        String str3 = null;
        Integer num = null;
        List list2 = null;
        Integer num2 = null;
        List list3 = null;
        Boolean bool = null;
        Boolean bool2 = null;
        String str4 = null;
        String str5 = null;
        while (true) {
            String str6 = str;
            String str7 = str2;
            List list4 = list;
            Map map2 = map;
            String str8 = str3;
            Integer num3 = num;
            List list5 = list2;
            Integer num4 = num2;
            List list6 = list3;
            if (!reader.l()) {
                Boolean bool3 = bool;
                reader.i();
                if (i == -4361) {
                    if (str6 == null) {
                        throw com.squareup.moshi.internal.b.e("questionUuid", "questionUuid", reader);
                    }
                    if (str7 == null) {
                        throw com.squareup.moshi.internal.b.e("question", "question", reader);
                    }
                    if (list4 == null) {
                        throw com.squareup.moshi.internal.b.e("answer", "answer", reader);
                    }
                    if (str8 == null) {
                        throw com.squareup.moshi.internal.b.e("questionFormat", "questionFormat", reader);
                    }
                    if (num3 == null) {
                        throw com.squareup.moshi.internal.b.e("questionIndex", "questionIndex", reader);
                    }
                    int iIntValue = num3.intValue();
                    if (list5 == null) {
                        throw com.squareup.moshi.internal.b.e("userAnswer", "userAnswer", reader);
                    }
                    if (num4 == null) {
                        throw com.squareup.moshi.internal.b.e("grade", "grade", reader);
                    }
                    int iIntValue2 = num4.intValue();
                    if (bool3 == null) {
                        throw com.squareup.moshi.internal.b.e("active", "active", reader);
                    }
                    Boolean bool4 = bool2;
                    boolean zBooleanValue = bool3.booleanValue();
                    if (bool4 == null) {
                        throw com.squareup.moshi.internal.b.e("excluded", "excluded", reader);
                    }
                    String str9 = str5;
                    String str10 = str4;
                    boolean zBooleanValue2 = bool4.booleanValue();
                    if (str10 != null) {
                        return new PracticeTestGradedQuestionResponse(str6, str7, list4, map2, str8, iIntValue, list5, iIntValue2, list6, zBooleanValue, zBooleanValue2, str10, str9);
                    }
                    throw com.squareup.moshi.internal.b.e("contentFormat", "contentFormat", reader);
                }
                Boolean bool5 = bool2;
                String str11 = str5;
                String str12 = str4;
                Constructor declaredConstructor = this.i;
                if (declaredConstructor == null) {
                    Class cls = com.squareup.moshi.internal.b.c;
                    Class cls2 = Boolean.TYPE;
                    Class cls3 = Integer.TYPE;
                    declaredConstructor = PracticeTestGradedQuestionResponse.class.getDeclaredConstructor(String.class, String.class, List.class, Map.class, String.class, cls3, List.class, cls3, List.class, cls2, cls2, String.class, String.class, cls3, cls);
                    this.i = declaredConstructor;
                    Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
                }
                if (str6 == null) {
                    throw com.squareup.moshi.internal.b.e("questionUuid", "questionUuid", reader);
                }
                if (str7 == null) {
                    throw com.squareup.moshi.internal.b.e("question", "question", reader);
                }
                if (list4 == null) {
                    throw com.squareup.moshi.internal.b.e("answer", "answer", reader);
                }
                if (str8 == null) {
                    throw com.squareup.moshi.internal.b.e("questionFormat", "questionFormat", reader);
                }
                if (num3 == null) {
                    throw com.squareup.moshi.internal.b.e("questionIndex", "questionIndex", reader);
                }
                if (list5 == null) {
                    throw com.squareup.moshi.internal.b.e("userAnswer", "userAnswer", reader);
                }
                if (num4 == null) {
                    throw com.squareup.moshi.internal.b.e("grade", "grade", reader);
                }
                if (bool3 == null) {
                    throw com.squareup.moshi.internal.b.e("active", "active", reader);
                }
                if (bool5 == null) {
                    throw com.squareup.moshi.internal.b.e("excluded", "excluded", reader);
                }
                if (str12 == null) {
                    throw com.squareup.moshi.internal.b.e("contentFormat", "contentFormat", reader);
                }
                Object objNewInstance = declaredConstructor.newInstance(str6, str7, list4, map2, str8, num3, list5, num4, list6, bool3, bool5, str12, str11, Integer.valueOf(i), null);
                Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
                return (PracticeTestGradedQuestionResponse) objNewInstance;
            }
            Boolean bool6 = bool;
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    bool = bool6;
                    str = str6;
                    str2 = str7;
                    list = list4;
                    map = map2;
                    str3 = str8;
                    num = num3;
                    list2 = list5;
                    num2 = num4;
                    list3 = list6;
                case 0:
                    str = (String) this.b.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("questionUuid", "questionUuid", reader);
                    }
                    bool = bool6;
                    str2 = str7;
                    list = list4;
                    map = map2;
                    str3 = str8;
                    num = num3;
                    list2 = list5;
                    num2 = num4;
                    list3 = list6;
                case 1:
                    str2 = (String) this.b.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("question", "question", reader);
                    }
                    bool = bool6;
                    str = str6;
                    list = list4;
                    map = map2;
                    str3 = str8;
                    num = num3;
                    list2 = list5;
                    num2 = num4;
                    list3 = list6;
                case 2:
                    list = (List) this.c.a(reader);
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.k("answer", "answer", reader);
                    }
                    bool = bool6;
                    str = str6;
                    str2 = str7;
                    map = map2;
                    str3 = str8;
                    num = num3;
                    list2 = list5;
                    num2 = num4;
                    list3 = list6;
                case 3:
                    map = (Map) this.d.a(reader);
                    i &= -9;
                    bool = bool6;
                    str = str6;
                    str2 = str7;
                    list = list4;
                    str3 = str8;
                    num = num3;
                    list2 = list5;
                    num2 = num4;
                    list3 = list6;
                case 4:
                    str3 = (String) this.b.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("questionFormat", "questionFormat", reader);
                    }
                    bool = bool6;
                    str = str6;
                    str2 = str7;
                    list = list4;
                    map = map2;
                    num = num3;
                    list2 = list5;
                    num2 = num4;
                    list3 = list6;
                case 5:
                    num = (Integer) this.e.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("questionIndex", "questionIndex", reader);
                    }
                    bool = bool6;
                    str = str6;
                    str2 = str7;
                    list = list4;
                    map = map2;
                    str3 = str8;
                    list2 = list5;
                    num2 = num4;
                    list3 = list6;
                case 6:
                    list2 = (List) this.c.a(reader);
                    if (list2 == null) {
                        throw com.squareup.moshi.internal.b.k("userAnswer", "userAnswer", reader);
                    }
                    bool = bool6;
                    str = str6;
                    str2 = str7;
                    list = list4;
                    map = map2;
                    str3 = str8;
                    num = num3;
                    num2 = num4;
                    list3 = list6;
                case 7:
                    num2 = (Integer) this.e.a(reader);
                    if (num2 == null) {
                        throw com.squareup.moshi.internal.b.k("grade", "grade", reader);
                    }
                    bool = bool6;
                    str = str6;
                    str2 = str7;
                    list = list4;
                    map = map2;
                    str3 = str8;
                    num = num3;
                    list2 = list5;
                    list3 = list6;
                case 8:
                    list3 = (List) this.f.a(reader);
                    i &= -257;
                    bool = bool6;
                    str = str6;
                    str2 = str7;
                    list = list4;
                    map = map2;
                    str3 = str8;
                    num = num3;
                    list2 = list5;
                    num2 = num4;
                case 9:
                    bool = (Boolean) this.g.a(reader);
                    if (bool == null) {
                        throw com.squareup.moshi.internal.b.k("active", "active", reader);
                    }
                    str = str6;
                    str2 = str7;
                    list = list4;
                    map = map2;
                    str3 = str8;
                    num = num3;
                    list2 = list5;
                    num2 = num4;
                    list3 = list6;
                case 10:
                    bool2 = (Boolean) this.g.a(reader);
                    if (bool2 == null) {
                        throw com.squareup.moshi.internal.b.k("excluded", "excluded", reader);
                    }
                    bool = bool6;
                    str = str6;
                    str2 = str7;
                    list = list4;
                    map = map2;
                    str3 = str8;
                    num = num3;
                    list2 = list5;
                    num2 = num4;
                    list3 = list6;
                case 11:
                    str4 = (String) this.b.a(reader);
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.k("contentFormat", "contentFormat", reader);
                    }
                    bool = bool6;
                    str = str6;
                    str2 = str7;
                    list = list4;
                    map = map2;
                    str3 = str8;
                    num = num3;
                    list2 = list5;
                    num2 = num4;
                    list3 = list6;
                case 12:
                    str5 = (String) this.h.a(reader);
                    i &= -4097;
                    bool = bool6;
                    str = str6;
                    str2 = str7;
                    list = list4;
                    map = map2;
                    str3 = str8;
                    num = num3;
                    list2 = list5;
                    num2 = num4;
                    list3 = list6;
                default:
                    bool = bool6;
                    str = str6;
                    str2 = str7;
                    list = list4;
                    map = map2;
                    str3 = str8;
                    num = num3;
                    list2 = list5;
                    num2 = num4;
                    list3 = list6;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        PracticeTestGradedQuestionResponse practiceTestGradedQuestionResponse = (PracticeTestGradedQuestionResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (practiceTestGradedQuestionResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("questionUuid");
        l lVar = this.b;
        lVar.g(writer, practiceTestGradedQuestionResponse.a);
        writer.l("question");
        lVar.g(writer, practiceTestGradedQuestionResponse.b);
        writer.l("answer");
        l lVar2 = this.c;
        lVar2.g(writer, practiceTestGradedQuestionResponse.c);
        writer.l("answerOptions");
        this.d.g(writer, practiceTestGradedQuestionResponse.d);
        writer.l("questionFormat");
        lVar.g(writer, practiceTestGradedQuestionResponse.e);
        writer.l("questionIndex");
        Integer numValueOf = Integer.valueOf(practiceTestGradedQuestionResponse.f);
        l lVar3 = this.e;
        lVar3.g(writer, numValueOf);
        writer.l("userAnswer");
        lVar2.g(writer, practiceTestGradedQuestionResponse.g);
        writer.l("grade");
        AbstractC4178x.p(practiceTestGradedQuestionResponse.h, lVar3, writer, "images");
        this.f.g(writer, practiceTestGradedQuestionResponse.i);
        writer.l("active");
        Boolean boolValueOf = Boolean.valueOf(practiceTestGradedQuestionResponse.j);
        l lVar4 = this.g;
        lVar4.g(writer, boolValueOf);
        writer.l("excluded");
        Z.q(practiceTestGradedQuestionResponse.k, lVar4, writer, "contentFormat");
        lVar.g(writer, practiceTestGradedQuestionResponse.l);
        writer.l("mediaType");
        this.h.g(writer, practiceTestGradedQuestionResponse.m);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(56, "GeneratedJsonAdapter(PracticeTestGradedQuestionResponse)", "toString(...)");
    }
}
