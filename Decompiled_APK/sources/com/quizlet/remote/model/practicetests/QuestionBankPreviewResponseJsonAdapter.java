package com.quizlet.remote.model.practicetests;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.entitlements.RemoteEntitlementData;
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
public final class QuestionBankPreviewResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public volatile Constructor d;

    public QuestionBankPreviewResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("questionBankPreview", "entitlementData");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, QuestionBankPreview.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "questionBankPreview");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, RemoteEntitlementData.class), m, "entitlementData");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        List list2 = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
                if (list == null) {
                    throw com.squareup.moshi.internal.b.k("questionBankPreview", "questionBankPreview", reader);
                }
                i &= -2;
            } else if (iK0 == 1) {
                list2 = (List) this.c.a(reader);
                if (list2 == null) {
                    throw com.squareup.moshi.internal.b.k("entitlementData", "entitlementData", reader);
                }
                i &= -3;
            } else {
                continue;
            }
        }
        reader.i();
        if (i == -4) {
            Intrinsics.e(list, "null cannot be cast to non-null type kotlin.collections.List<com.quizlet.remote.model.practicetests.QuestionBankPreview>");
            Intrinsics.e(list2, "null cannot be cast to non-null type kotlin.collections.List<com.quizlet.remote.model.entitlements.RemoteEntitlementData>");
            return new QuestionBankPreviewResponse(list, list2);
        }
        Constructor declaredConstructor = this.d;
        if (declaredConstructor == null) {
            declaredConstructor = QuestionBankPreviewResponse.class.getDeclaredConstructor(List.class, List.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.d = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(list, list2, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (QuestionBankPreviewResponse) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        QuestionBankPreviewResponse questionBankPreviewResponse = (QuestionBankPreviewResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (questionBankPreviewResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("questionBankPreview");
        this.b.g(writer, questionBankPreviewResponse.a);
        writer.l("entitlementData");
        this.c.g(writer, questionBankPreviewResponse.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(49, "GeneratedJsonAdapter(QuestionBankPreviewResponse)", "toString(...)");
    }
}
