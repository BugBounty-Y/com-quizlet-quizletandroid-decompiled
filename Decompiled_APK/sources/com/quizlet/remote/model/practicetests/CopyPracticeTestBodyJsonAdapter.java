package com.quizlet.remote.model.practicetests;

import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class CopyPracticeTestBodyJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;

    public CopyPracticeTestBodyJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("questionBankUuid", "practiceTestUuid");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(String.class, M.a, "questionBankUuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("questionBankUuid", "questionBankUuid", reader);
                    }
                } else if (iK0 == 1 && (str2 = (String) lVar.a(reader)) == null) {
                    throw com.squareup.moshi.internal.b.k("practiceTestUuid", "practiceTestUuid", reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("questionBankUuid", "questionBankUuid", reader);
        }
        if (str2 != null) {
            return new CopyPracticeTestBody(str, str2);
        }
        throw com.squareup.moshi.internal.b.e("practiceTestUuid", "practiceTestUuid", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        CopyPracticeTestBody copyPracticeTestBody = (CopyPracticeTestBody) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (copyPracticeTestBody == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("questionBankUuid");
        String str = copyPracticeTestBody.a;
        l lVar = this.b;
        lVar.g(writer, str);
        writer.l("practiceTestUuid");
        lVar.g(writer, copyPracticeTestBody.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(42, "GeneratedJsonAdapter(CopyPracticeTestBody)", "toString(...)");
    }
}
