package com.quizlet.remote.model.practicetests;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.remote.model.user.RemoteFullUser;
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
public final class QuestionBankPreviewJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public final l g;
    public final l h;
    public final l i;
    public volatile Constructor j;

    public QuestionBankPreviewJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "name", "nameSlug", "questions", "createdAt", "course", "school", AssociationNames.CREATOR, "metadata", "private", "questionCounts");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, PracticeTestsQuestionResponse.class), m, "questions");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(PracticeTestCourse.class, m, "course");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(PracticeTestSchool.class, m, "school");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(RemoteFullUser.class, m, AssociationNames.CREATOR);
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(QuestionBankMetadataResponse.class, m, "metadata");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
        l lVarA7 = moshi.a(Boolean.TYPE, m, "private");
        Intrinsics.checkNotNullExpressionValue(lVarA7, "adapter(...)");
        this.h = lVarA7;
        l lVarA8 = moshi.a(H.f(Map.class, String.class, Integer.class), m, "questionCounts");
        Intrinsics.checkNotNullExpressionValue(lVarA8, "adapter(...)");
        this.i = lVarA8;
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
        PracticeTestCourse practiceTestCourse = null;
        PracticeTestSchool practiceTestSchool = null;
        RemoteFullUser remoteFullUser = null;
        QuestionBankMetadataResponse questionBankMetadataResponse = null;
        Boolean bool = null;
        Map map = null;
        while (true) {
            String str5 = str;
            String str6 = str2;
            String str7 = str3;
            List list2 = list;
            String str8 = str4;
            PracticeTestCourse practiceTestCourse2 = practiceTestCourse;
            if (!reader.l()) {
                PracticeTestSchool practiceTestSchool2 = practiceTestSchool;
                reader.i();
                if (i2 == -481) {
                    if (str5 == null) {
                        throw com.squareup.moshi.internal.b.e("id", "id", reader);
                    }
                    if (str6 == null) {
                        throw com.squareup.moshi.internal.b.e("name", "name", reader);
                    }
                    if (str7 == null) {
                        throw com.squareup.moshi.internal.b.e("nameSlug", "nameSlug", reader);
                    }
                    if (list2 == null) {
                        throw com.squareup.moshi.internal.b.e("questions", "questions", reader);
                    }
                    if (str8 == null) {
                        throw com.squareup.moshi.internal.b.e("createdAt", "createdAt", reader);
                    }
                    if (bool == null) {
                        throw com.squareup.moshi.internal.b.e("private_", "private", reader);
                    }
                    Map map2 = map;
                    boolean zBooleanValue = bool.booleanValue();
                    if (map2 == null) {
                        throw com.squareup.moshi.internal.b.e("questionCounts", "questionCounts", reader);
                    }
                    return new QuestionBankPreview(str5, str6, str7, list2, str8, practiceTestCourse2, practiceTestSchool2, remoteFullUser, questionBankMetadataResponse, zBooleanValue, map2);
                }
                Map map3 = map;
                Constructor declaredConstructor = this.j;
                if (declaredConstructor == null) {
                    i = i2;
                    declaredConstructor = QuestionBankPreview.class.getDeclaredConstructor(String.class, String.class, String.class, List.class, String.class, PracticeTestCourse.class, PracticeTestSchool.class, RemoteFullUser.class, QuestionBankMetadataResponse.class, Boolean.TYPE, Map.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
                    this.j = declaredConstructor;
                    Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
                } else {
                    i = i2;
                }
                Constructor constructor = declaredConstructor;
                if (str5 == null) {
                    throw com.squareup.moshi.internal.b.e("id", "id", reader);
                }
                if (str6 == null) {
                    throw com.squareup.moshi.internal.b.e("name", "name", reader);
                }
                if (str7 == null) {
                    throw com.squareup.moshi.internal.b.e("nameSlug", "nameSlug", reader);
                }
                if (list2 == null) {
                    throw com.squareup.moshi.internal.b.e("questions", "questions", reader);
                }
                if (str8 == null) {
                    throw com.squareup.moshi.internal.b.e("createdAt", "createdAt", reader);
                }
                if (bool == null) {
                    throw com.squareup.moshi.internal.b.e("private_", "private", reader);
                }
                if (map3 == null) {
                    throw com.squareup.moshi.internal.b.e("questionCounts", "questionCounts", reader);
                }
                Object objNewInstance = constructor.newInstance(str5, str6, str7, list2, str8, practiceTestCourse2, practiceTestSchool2, remoteFullUser, questionBankMetadataResponse, bool, map3, Integer.valueOf(i), null);
                Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
                return (QuestionBankPreview) objNewInstance;
            }
            PracticeTestSchool practiceTestSchool3 = practiceTestSchool;
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    practiceTestSchool = practiceTestSchool3;
                    str = str5;
                    str2 = str6;
                    str3 = str7;
                    list = list2;
                    str4 = str8;
                    practiceTestCourse = practiceTestCourse2;
                case 0:
                    String str9 = (String) this.b.a(reader);
                    if (str9 == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    str = str9;
                    practiceTestSchool = practiceTestSchool3;
                    str2 = str6;
                    str3 = str7;
                    list = list2;
                    str4 = str8;
                    practiceTestCourse = practiceTestCourse2;
                case 1:
                    String str10 = (String) this.b.a(reader);
                    if (str10 == null) {
                        throw com.squareup.moshi.internal.b.k("name", "name", reader);
                    }
                    str2 = str10;
                    practiceTestSchool = practiceTestSchool3;
                    str = str5;
                    str3 = str7;
                    list = list2;
                    str4 = str8;
                    practiceTestCourse = practiceTestCourse2;
                case 2:
                    String str11 = (String) this.b.a(reader);
                    if (str11 == null) {
                        throw com.squareup.moshi.internal.b.k("nameSlug", "nameSlug", reader);
                    }
                    str3 = str11;
                    practiceTestSchool = practiceTestSchool3;
                    str = str5;
                    str2 = str6;
                    list = list2;
                    str4 = str8;
                    practiceTestCourse = practiceTestCourse2;
                case 3:
                    List list3 = (List) this.c.a(reader);
                    if (list3 == null) {
                        throw com.squareup.moshi.internal.b.k("questions", "questions", reader);
                    }
                    list = list3;
                    practiceTestSchool = practiceTestSchool3;
                    str = str5;
                    str2 = str6;
                    str3 = str7;
                    str4 = str8;
                    practiceTestCourse = practiceTestCourse2;
                case 4:
                    String str12 = (String) this.b.a(reader);
                    if (str12 == null) {
                        throw com.squareup.moshi.internal.b.k("createdAt", "createdAt", reader);
                    }
                    str4 = str12;
                    practiceTestSchool = practiceTestSchool3;
                    str = str5;
                    str2 = str6;
                    str3 = str7;
                    list = list2;
                    practiceTestCourse = practiceTestCourse2;
                case 5:
                    practiceTestCourse = (PracticeTestCourse) this.d.a(reader);
                    i2 &= -33;
                    practiceTestSchool = practiceTestSchool3;
                    str = str5;
                    str2 = str6;
                    str3 = str7;
                    list = list2;
                    str4 = str8;
                case 6:
                    practiceTestSchool = (PracticeTestSchool) this.e.a(reader);
                    i2 &= -65;
                    str = str5;
                    str2 = str6;
                    str3 = str7;
                    list = list2;
                    str4 = str8;
                    practiceTestCourse = practiceTestCourse2;
                case 7:
                    remoteFullUser = (RemoteFullUser) this.f.a(reader);
                    i2 &= -129;
                    practiceTestSchool = practiceTestSchool3;
                    str = str5;
                    str2 = str6;
                    str3 = str7;
                    list = list2;
                    str4 = str8;
                    practiceTestCourse = practiceTestCourse2;
                case 8:
                    questionBankMetadataResponse = (QuestionBankMetadataResponse) this.g.a(reader);
                    i2 &= -257;
                    practiceTestSchool = practiceTestSchool3;
                    str = str5;
                    str2 = str6;
                    str3 = str7;
                    list = list2;
                    str4 = str8;
                    practiceTestCourse = practiceTestCourse2;
                case 9:
                    bool = (Boolean) this.h.a(reader);
                    if (bool == null) {
                        throw com.squareup.moshi.internal.b.k("private_", "private", reader);
                    }
                    practiceTestSchool = practiceTestSchool3;
                    str = str5;
                    str2 = str6;
                    str3 = str7;
                    list = list2;
                    str4 = str8;
                    practiceTestCourse = practiceTestCourse2;
                case 10:
                    map = (Map) this.i.a(reader);
                    if (map == null) {
                        throw com.squareup.moshi.internal.b.k("questionCounts", "questionCounts", reader);
                    }
                    practiceTestSchool = practiceTestSchool3;
                    str = str5;
                    str2 = str6;
                    str3 = str7;
                    list = list2;
                    str4 = str8;
                    practiceTestCourse = practiceTestCourse2;
                default:
                    practiceTestSchool = practiceTestSchool3;
                    str = str5;
                    str2 = str6;
                    str3 = str7;
                    list = list2;
                    str4 = str8;
                    practiceTestCourse = practiceTestCourse2;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        QuestionBankPreview questionBankPreview = (QuestionBankPreview) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (questionBankPreview == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        l lVar = this.b;
        lVar.g(writer, questionBankPreview.a);
        writer.l("name");
        lVar.g(writer, questionBankPreview.b);
        writer.l("nameSlug");
        lVar.g(writer, questionBankPreview.c);
        writer.l("questions");
        this.c.g(writer, questionBankPreview.d);
        writer.l("createdAt");
        lVar.g(writer, questionBankPreview.e);
        writer.l("course");
        this.d.g(writer, questionBankPreview.f);
        writer.l("school");
        this.e.g(writer, questionBankPreview.g);
        writer.l(AssociationNames.CREATOR);
        this.f.g(writer, questionBankPreview.h);
        writer.l("metadata");
        this.g.g(writer, questionBankPreview.i);
        writer.l("private");
        this.h.g(writer, Boolean.valueOf(questionBankPreview.j));
        writer.l("questionCounts");
        this.i.g(writer, questionBankPreview.k);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(41, "GeneratedJsonAdapter(QuestionBankPreview)", "toString(...)");
    }
}
