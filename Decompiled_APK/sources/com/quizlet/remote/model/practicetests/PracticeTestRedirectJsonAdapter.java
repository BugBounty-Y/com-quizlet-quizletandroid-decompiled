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
public final class PracticeTestRedirectJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;

    public PracticeTestRedirectJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("destination", "questionBankUuid");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(String.class, M.a, "destination");
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
                        throw com.squareup.moshi.internal.b.k("destination", "destination", reader);
                    }
                } else if (iK0 == 1 && (str2 = (String) lVar.a(reader)) == null) {
                    throw com.squareup.moshi.internal.b.k("questionBankUuid", "questionBankUuid", reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("destination", "destination", reader);
        }
        if (str2 != null) {
            return new PracticeTestRedirect(str, str2);
        }
        throw com.squareup.moshi.internal.b.e("questionBankUuid", "questionBankUuid", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        PracticeTestRedirect practiceTestRedirect = (PracticeTestRedirect) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (practiceTestRedirect == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("destination");
        String str = practiceTestRedirect.a;
        l lVar = this.b;
        lVar.g(writer, str);
        writer.l("questionBankUuid");
        lVar.g(writer, practiceTestRedirect.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(42, "GeneratedJsonAdapter(PracticeTestRedirect)", "toString(...)");
    }
}
