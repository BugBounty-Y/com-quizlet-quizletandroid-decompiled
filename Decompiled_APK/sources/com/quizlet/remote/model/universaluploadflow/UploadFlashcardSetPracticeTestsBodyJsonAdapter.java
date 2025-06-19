package com.quizlet.remote.model.universaluploadflow;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.practicetests.QuestionCompatibility;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class UploadFlashcardSetPracticeTestsBodyJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public volatile Constructor f;

    public UploadFlashcardSetPracticeTestsBodyJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("setIds", "private", "inputType", "entryPoint", "questionCompatibility");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, Long.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "setIds");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Boolean.TYPE, m, "private");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(String.class, m, "inputType");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(QuestionCompatibility.class, m, "questionCompatibility");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        Boolean bool = null;
        String str = null;
        String str2 = null;
        QuestionCompatibility questionCompatibility = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
                if (list == null) {
                    throw com.squareup.moshi.internal.b.k("setIds", "setIds", reader);
                }
            } else if (iK0 == 1) {
                bool = (Boolean) this.c.a(reader);
                if (bool == null) {
                    throw com.squareup.moshi.internal.b.k("private_", "private", reader);
                }
            } else if (iK0 == 2) {
                str = (String) this.d.a(reader);
                if (str == null) {
                    throw com.squareup.moshi.internal.b.k("inputType", "inputType", reader);
                }
                i &= -5;
            } else if (iK0 == 3) {
                str2 = (String) this.d.a(reader);
                if (str2 == null) {
                    throw com.squareup.moshi.internal.b.k("entryPoint", "entryPoint", reader);
                }
                i &= -9;
            } else if (iK0 == 4) {
                questionCompatibility = (QuestionCompatibility) this.e.a(reader);
                if (questionCompatibility == null) {
                    throw com.squareup.moshi.internal.b.k("questionCompatibility", "questionCompatibility", reader);
                }
                i &= -17;
            } else {
                continue;
            }
        }
        reader.i();
        if (i == -29) {
            Boolean bool2 = bool;
            List list2 = list;
            if (list2 == null) {
                throw com.squareup.moshi.internal.b.e("setIds", "setIds", reader);
            }
            if (bool2 == null) {
                throw com.squareup.moshi.internal.b.e("private_", "private", reader);
            }
            boolean zBooleanValue = bool2.booleanValue();
            Intrinsics.e(str, "null cannot be cast to non-null type kotlin.String");
            Intrinsics.e(str2, "null cannot be cast to non-null type kotlin.String");
            Intrinsics.e(questionCompatibility, "null cannot be cast to non-null type com.quizlet.remote.model.practicetests.QuestionCompatibility");
            return new UploadFlashcardSetPracticeTestsBody(list2, zBooleanValue, str, str2, questionCompatibility);
        }
        Boolean bool3 = bool;
        List list3 = list;
        Constructor declaredConstructor = this.f;
        if (declaredConstructor == null) {
            declaredConstructor = UploadFlashcardSetPracticeTestsBody.class.getDeclaredConstructor(List.class, Boolean.TYPE, String.class, String.class, QuestionCompatibility.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.f = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Constructor constructor = declaredConstructor;
        if (list3 == null) {
            throw com.squareup.moshi.internal.b.e("setIds", "setIds", reader);
        }
        if (bool3 == null) {
            throw com.squareup.moshi.internal.b.e("private_", "private", reader);
        }
        Object objNewInstance = constructor.newInstance(list3, bool3, str, str2, questionCompatibility, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (UploadFlashcardSetPracticeTestsBody) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        UploadFlashcardSetPracticeTestsBody uploadFlashcardSetPracticeTestsBody = (UploadFlashcardSetPracticeTestsBody) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (uploadFlashcardSetPracticeTestsBody == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("setIds");
        this.b.g(writer, uploadFlashcardSetPracticeTestsBody.a);
        writer.l("private");
        this.c.g(writer, Boolean.valueOf(uploadFlashcardSetPracticeTestsBody.b));
        writer.l("inputType");
        l lVar = this.d;
        lVar.g(writer, uploadFlashcardSetPracticeTestsBody.c);
        writer.l("entryPoint");
        lVar.g(writer, uploadFlashcardSetPracticeTestsBody.d);
        writer.l("questionCompatibility");
        this.e.g(writer, uploadFlashcardSetPracticeTestsBody.e);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(57, "GeneratedJsonAdapter(UploadFlashcardSetPracticeTestsBody)", "toString(...)");
    }
}
