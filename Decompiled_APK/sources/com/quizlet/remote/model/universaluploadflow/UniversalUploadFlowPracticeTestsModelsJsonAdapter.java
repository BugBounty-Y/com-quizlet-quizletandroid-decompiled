package com.quizlet.remote.model.universaluploadflow;

import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
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
public final class UniversalUploadFlowPracticeTestsModelsJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;

    public UniversalUploadFlowPracticeTestsModelsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("document", "qbp");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, UniversalUploadFlowPracticeTestsDocuments.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "document");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, Integer.class), m, "qbp");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        List list2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
                if (list == null) {
                    throw com.squareup.moshi.internal.b.k("document", "document", reader);
                }
            } else if (iK0 == 1 && (list2 = (List) this.c.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("qbp", "qbp", reader);
            }
        }
        reader.i();
        if (list == null) {
            throw com.squareup.moshi.internal.b.e("document", "document", reader);
        }
        if (list2 != null) {
            return new UniversalUploadFlowPracticeTestsModels(list, list2);
        }
        throw com.squareup.moshi.internal.b.e("qbp", "qbp", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        UniversalUploadFlowPracticeTestsModels universalUploadFlowPracticeTestsModels = (UniversalUploadFlowPracticeTestsModels) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (universalUploadFlowPracticeTestsModels == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("document");
        this.b.g(writer, universalUploadFlowPracticeTestsModels.a);
        writer.l("qbp");
        this.c.g(writer, universalUploadFlowPracticeTestsModels.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(60, "GeneratedJsonAdapter(UniversalUploadFlowPracticeTestsModels)", "toString(...)");
    }
}
