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
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteUpdateQuestionBankModelJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public volatile Constructor c;

    public RemoteUpdateQuestionBankModelJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("questionBank");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(H.f(List.class, RemoteQuestionBankUuid.class), M.a, "questionBank");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
                if (list == null) {
                    throw com.squareup.moshi.internal.b.k("questionBank", "questionBank", reader);
                }
                i = -2;
            } else {
                continue;
            }
        }
        reader.i();
        if (i == -2) {
            Intrinsics.e(list, "null cannot be cast to non-null type kotlin.collections.List<com.quizlet.remote.model.practicetests.RemoteQuestionBankUuid>");
            return new RemoteUpdateQuestionBankModel(list);
        }
        Constructor declaredConstructor = this.c;
        if (declaredConstructor == null) {
            declaredConstructor = RemoteUpdateQuestionBankModel.class.getDeclaredConstructor(List.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.c = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(list, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (RemoteUpdateQuestionBankModel) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteUpdateQuestionBankModel remoteUpdateQuestionBankModel = (RemoteUpdateQuestionBankModel) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteUpdateQuestionBankModel == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("questionBank");
        this.b.g(writer, remoteUpdateQuestionBankModel.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(51, "GeneratedJsonAdapter(RemoteUpdateQuestionBankModel)", "toString(...)");
    }
}
