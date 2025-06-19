package com.quizlet.remote.model.universaluploadflow;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.practicetests.QuestionCompatibility;
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
public final class UploadTextPracticeTestsBodyJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public volatile Constructor e;

    public UploadTextPracticeTestsBodyJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("text", "private", "questionCompatibility", "inputType");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "text");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Boolean.TYPE, m, "private");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(QuestionCompatibility.class, m, "questionCompatibility");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        Boolean bool = null;
        QuestionCompatibility questionCompatibility = null;
        String str2 = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                str = (String) this.b.a(reader);
                if (str == null) {
                    throw com.squareup.moshi.internal.b.k("text", "text", reader);
                }
            } else if (iK0 == 1) {
                bool = (Boolean) this.c.a(reader);
                if (bool == null) {
                    throw com.squareup.moshi.internal.b.k("private_", "private", reader);
                }
            } else if (iK0 == 2) {
                questionCompatibility = (QuestionCompatibility) this.d.a(reader);
                if (questionCompatibility == null) {
                    throw com.squareup.moshi.internal.b.k("questionCompatibility", "questionCompatibility", reader);
                }
                i &= -5;
            } else if (iK0 == 3) {
                str2 = (String) this.b.a(reader);
                if (str2 == null) {
                    throw com.squareup.moshi.internal.b.k("inputType", "inputType", reader);
                }
                i &= -9;
            } else {
                continue;
            }
        }
        reader.i();
        if (i == -13) {
            if (str == null) {
                throw com.squareup.moshi.internal.b.e("text", "text", reader);
            }
            if (bool == null) {
                throw com.squareup.moshi.internal.b.e("private_", "private", reader);
            }
            boolean zBooleanValue = bool.booleanValue();
            Intrinsics.e(questionCompatibility, "null cannot be cast to non-null type com.quizlet.remote.model.practicetests.QuestionCompatibility");
            Intrinsics.e(str2, "null cannot be cast to non-null type kotlin.String");
            return new UploadTextPracticeTestsBody(str, zBooleanValue, questionCompatibility, str2);
        }
        Constructor declaredConstructor = this.e;
        if (declaredConstructor == null) {
            declaredConstructor = UploadTextPracticeTestsBody.class.getDeclaredConstructor(String.class, Boolean.TYPE, QuestionCompatibility.class, String.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.e = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("text", "text", reader);
        }
        if (bool == null) {
            throw com.squareup.moshi.internal.b.e("private_", "private", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(str, bool, questionCompatibility, str2, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (UploadTextPracticeTestsBody) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        UploadTextPracticeTestsBody uploadTextPracticeTestsBody = (UploadTextPracticeTestsBody) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (uploadTextPracticeTestsBody == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("text");
        l lVar = this.b;
        lVar.g(writer, uploadTextPracticeTestsBody.a);
        writer.l("private");
        this.c.g(writer, Boolean.valueOf(uploadTextPracticeTestsBody.b));
        writer.l("questionCompatibility");
        this.d.g(writer, uploadTextPracticeTestsBody.c);
        writer.l("inputType");
        lVar.g(writer, uploadTextPracticeTestsBody.d);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(49, "GeneratedJsonAdapter(UploadTextPracticeTestsBody)", "toString(...)");
    }
}
