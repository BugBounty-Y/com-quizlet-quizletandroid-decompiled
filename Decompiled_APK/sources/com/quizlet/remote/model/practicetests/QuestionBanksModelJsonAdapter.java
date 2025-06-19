package com.quizlet.remote.model.practicetests;

import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class QuestionBanksModelJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public volatile Constructor f;

    public QuestionBanksModelJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("questionBankUuid", "name", "createdAt", "private", "creatorId", "documentType", "fileName", "uploadEntryPoint");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "questionBankUuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Boolean.class, m, "private");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Long.TYPE, m, "creatorId");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(String.class, m, "fileName");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
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
        Boolean bool = null;
        Long l = null;
        String str4 = null;
        String str5 = null;
        String str6 = null;
        while (reader.l()) {
            String str7 = str;
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    str = (String) this.b.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("questionBankUuid", "questionBankUuid", reader);
                    }
                    continue;
                case 1:
                    str2 = (String) this.b.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("name", "name", reader);
                    }
                    break;
                case 2:
                    str3 = (String) this.b.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("createdAt", "createdAt", reader);
                    }
                    break;
                case 3:
                    bool = (Boolean) this.c.a(reader);
                    i2 &= -9;
                    break;
                case 4:
                    l = (Long) this.d.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("creatorId", "creatorId", reader);
                    }
                    break;
                case 5:
                    str4 = (String) this.b.a(reader);
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.k("documentType", "documentType", reader);
                    }
                    break;
                case 6:
                    str5 = (String) this.e.a(reader);
                    i2 &= -65;
                    break;
                case 7:
                    str6 = (String) this.e.a(reader);
                    i2 &= -129;
                    break;
            }
            str = str7;
        }
        String str8 = str;
        reader.i();
        if (i2 == -201) {
            if (str8 == null) {
                throw com.squareup.moshi.internal.b.e("questionBankUuid", "questionBankUuid", reader);
            }
            if (str2 == null) {
                throw com.squareup.moshi.internal.b.e("name", "name", reader);
            }
            if (str3 == null) {
                throw com.squareup.moshi.internal.b.e("createdAt", "createdAt", reader);
            }
            if (l == null) {
                throw com.squareup.moshi.internal.b.e("creatorId", "creatorId", reader);
            }
            String str9 = str5;
            String str10 = str6;
            String str11 = str4;
            long jLongValue = l.longValue();
            if (str11 == null) {
                throw com.squareup.moshi.internal.b.e("documentType", "documentType", reader);
            }
            return new QuestionBanksModel(str8, str2, str3, bool, jLongValue, str11, str9, str10);
        }
        String str12 = str6;
        String str13 = str4;
        Constructor declaredConstructor = this.f;
        if (declaredConstructor == null) {
            i = i2;
            declaredConstructor = QuestionBanksModel.class.getDeclaredConstructor(String.class, String.class, String.class, Boolean.class, Long.TYPE, String.class, String.class, String.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.f = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        } else {
            i = i2;
        }
        Constructor constructor = declaredConstructor;
        if (str8 == null) {
            throw com.squareup.moshi.internal.b.e("questionBankUuid", "questionBankUuid", reader);
        }
        if (str2 == null) {
            throw com.squareup.moshi.internal.b.e("name", "name", reader);
        }
        if (str3 == null) {
            throw com.squareup.moshi.internal.b.e("createdAt", "createdAt", reader);
        }
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("creatorId", "creatorId", reader);
        }
        if (str13 == null) {
            throw com.squareup.moshi.internal.b.e("documentType", "documentType", reader);
        }
        Object objNewInstance = constructor.newInstance(str8, str2, str3, bool, l, str13, str5, str12, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (QuestionBanksModel) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        QuestionBanksModel questionBanksModel = (QuestionBanksModel) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (questionBanksModel == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("questionBankUuid");
        l lVar = this.b;
        lVar.g(writer, questionBanksModel.a);
        writer.l("name");
        lVar.g(writer, questionBanksModel.b);
        writer.l("createdAt");
        lVar.g(writer, questionBanksModel.c);
        writer.l("private");
        this.c.g(writer, questionBanksModel.d);
        writer.l("creatorId");
        this.d.g(writer, Long.valueOf(questionBanksModel.e));
        writer.l("documentType");
        lVar.g(writer, questionBanksModel.f);
        writer.l("fileName");
        l lVar2 = this.e;
        lVar2.g(writer, questionBanksModel.g);
        writer.l("uploadEntryPoint");
        lVar2.g(writer, questionBanksModel.h);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(40, "GeneratedJsonAdapter(QuestionBanksModel)", "toString(...)");
    }
}
