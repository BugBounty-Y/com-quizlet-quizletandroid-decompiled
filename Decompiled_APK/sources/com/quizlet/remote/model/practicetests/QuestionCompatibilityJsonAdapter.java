package com.quizlet.remote.model.practicetests;

import com.quizlet.data.model.AbstractC4178x;
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
public final class QuestionCompatibilityJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public volatile Constructor d;

    public QuestionCompatibilityJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("questionFormats", "contentFormats", "mediaTypes");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, String.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "questionFormats");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, String.class), m, "mediaTypes");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        List list2 = null;
        List list3 = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
                if (list == null) {
                    throw com.squareup.moshi.internal.b.k("questionFormats", "questionFormats", reader);
                }
                i &= -2;
            } else if (iK0 == 1) {
                list2 = (List) this.b.a(reader);
                if (list2 == null) {
                    throw com.squareup.moshi.internal.b.k("contentFormats", "contentFormats", reader);
                }
                i &= -3;
            } else if (iK0 == 2) {
                list3 = (List) this.c.a(reader);
                i &= -5;
            }
        }
        reader.i();
        if (i == -8) {
            Intrinsics.e(list, "null cannot be cast to non-null type kotlin.collections.List<kotlin.String>");
            Intrinsics.e(list2, "null cannot be cast to non-null type kotlin.collections.List<kotlin.String>");
            return new QuestionCompatibility(list, list2, list3);
        }
        Constructor declaredConstructor = this.d;
        if (declaredConstructor == null) {
            declaredConstructor = QuestionCompatibility.class.getDeclaredConstructor(List.class, List.class, List.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.d = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(list, list2, list3, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (QuestionCompatibility) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        QuestionCompatibility questionCompatibility = (QuestionCompatibility) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (questionCompatibility == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("questionFormats");
        l lVar = this.b;
        lVar.g(writer, questionCompatibility.a);
        writer.l("contentFormats");
        lVar.g(writer, questionCompatibility.b);
        writer.l("mediaTypes");
        this.c.g(writer, questionCompatibility.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(43, "GeneratedJsonAdapter(QuestionCompatibility)", "toString(...)");
    }
}
