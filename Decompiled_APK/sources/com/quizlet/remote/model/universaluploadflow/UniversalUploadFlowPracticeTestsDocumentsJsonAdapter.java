package com.quizlet.remote.model.universaluploadflow;

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
public final class UniversalUploadFlowPracticeTestsDocumentsJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;

    public UniversalUploadFlowPracticeTestsDocumentsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("questionBankId");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(String.class, M.a, "questionBankId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (str = (String) this.b.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("questionBankId", "questionBankId", reader);
            }
        }
        reader.i();
        if (str != null) {
            return new UniversalUploadFlowPracticeTestsDocuments(str);
        }
        throw com.squareup.moshi.internal.b.e("questionBankId", "questionBankId", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        UniversalUploadFlowPracticeTestsDocuments universalUploadFlowPracticeTestsDocuments = (UniversalUploadFlowPracticeTestsDocuments) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (universalUploadFlowPracticeTestsDocuments == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("questionBankId");
        this.b.g(writer, universalUploadFlowPracticeTestsDocuments.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(63, "GeneratedJsonAdapter(UniversalUploadFlowPracticeTestsDocuments)", "toString(...)");
    }
}
