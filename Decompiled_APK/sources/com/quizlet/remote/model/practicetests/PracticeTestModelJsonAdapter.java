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
public final class PracticeTestModelJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;

    public PracticeTestModelJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("practiceTestUuid", "name", "nameSlug", "userId", "questionBankUuid", "questionBankName", "configuration", "questions");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "practiceTestUuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Long.TYPE, m, "userId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(PracticeTestConfigurationResponse.class, m, "configuration");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(H.f(List.class, PracticeTestsQuestionResponse.class), m, "questions");
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
        String str3 = null;
        String str4 = null;
        String str5 = null;
        PracticeTestConfigurationResponse practiceTestConfigurationResponse = null;
        List list = null;
        while (true) {
            Long l2 = l;
            String str6 = str;
            if (!reader.l()) {
                String str7 = str2;
                reader.i();
                if (str6 == null) {
                    throw com.squareup.moshi.internal.b.e("practiceTestUuid", "practiceTestUuid", reader);
                }
                if (str7 == null) {
                    throw com.squareup.moshi.internal.b.e("name", "name", reader);
                }
                if (str3 == null) {
                    throw com.squareup.moshi.internal.b.e("nameSlug", "nameSlug", reader);
                }
                if (l2 == null) {
                    throw com.squareup.moshi.internal.b.e("userId", "userId", reader);
                }
                long jLongValue = l2.longValue();
                if (str4 == null) {
                    throw com.squareup.moshi.internal.b.e("questionBankUuid", "questionBankUuid", reader);
                }
                if (str5 == null) {
                    throw com.squareup.moshi.internal.b.e("questionBankName", "questionBankName", reader);
                }
                if (practiceTestConfigurationResponse == null) {
                    throw com.squareup.moshi.internal.b.e("configuration", "configuration", reader);
                }
                if (list != null) {
                    return new PracticeTestModel(str6, str7, str3, jLongValue, str4, str5, practiceTestConfigurationResponse, list);
                }
                throw com.squareup.moshi.internal.b.e("questions", "questions", reader);
            }
            String str8 = str2;
            int iK0 = reader.k0(this.a);
            l lVar = this.b;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    l = l2;
                    str2 = str8;
                    str = str6;
                case 0:
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("practiceTestUuid", "practiceTestUuid", reader);
                    }
                    l = l2;
                    str2 = str8;
                case 1:
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("name", "name", reader);
                    }
                    l = l2;
                    str = str6;
                case 2:
                    str3 = (String) lVar.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("nameSlug", "nameSlug", reader);
                    }
                    l = l2;
                    str2 = str8;
                    str = str6;
                case 3:
                    l = (Long) this.c.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("userId", "userId", reader);
                    }
                    str2 = str8;
                    str = str6;
                case 4:
                    str4 = (String) lVar.a(reader);
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.k("questionBankUuid", "questionBankUuid", reader);
                    }
                    l = l2;
                    str2 = str8;
                    str = str6;
                case 5:
                    str5 = (String) lVar.a(reader);
                    if (str5 == null) {
                        throw com.squareup.moshi.internal.b.k("questionBankName", "questionBankName", reader);
                    }
                    l = l2;
                    str2 = str8;
                    str = str6;
                case 6:
                    practiceTestConfigurationResponse = (PracticeTestConfigurationResponse) this.d.a(reader);
                    if (practiceTestConfigurationResponse == null) {
                        throw com.squareup.moshi.internal.b.k("configuration", "configuration", reader);
                    }
                    l = l2;
                    str2 = str8;
                    str = str6;
                case 7:
                    list = (List) this.e.a(reader);
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.k("questions", "questions", reader);
                    }
                    l = l2;
                    str2 = str8;
                    str = str6;
                default:
                    l = l2;
                    str2 = str8;
                    str = str6;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        PracticeTestModel practiceTestModel = (PracticeTestModel) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (practiceTestModel == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("practiceTestUuid");
        String str = practiceTestModel.a;
        l lVar = this.b;
        lVar.g(writer, str);
        writer.l("name");
        lVar.g(writer, practiceTestModel.b);
        writer.l("nameSlug");
        lVar.g(writer, practiceTestModel.c);
        writer.l("userId");
        this.c.g(writer, Long.valueOf(practiceTestModel.d));
        writer.l("questionBankUuid");
        lVar.g(writer, practiceTestModel.e);
        writer.l("questionBankName");
        lVar.g(writer, practiceTestModel.f);
        writer.l("configuration");
        this.d.g(writer, practiceTestModel.g);
        writer.l("questions");
        this.e.g(writer, practiceTestModel.h);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(39, "GeneratedJsonAdapter(PracticeTestModel)", "toString(...)");
    }
}
