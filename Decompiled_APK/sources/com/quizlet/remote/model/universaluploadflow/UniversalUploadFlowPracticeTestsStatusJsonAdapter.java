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
public final class UniversalUploadFlowPracticeTestsStatusJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;

    public UniversalUploadFlowPracticeTestsStatusJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "status", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, "status");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(String.class, m, "error");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        Integer num = null;
        String str2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                str = (String) this.b.a(reader);
                if (str == null) {
                    throw com.squareup.moshi.internal.b.k("id", "id", reader);
                }
            } else if (iK0 == 1) {
                num = (Integer) this.c.a(reader);
                if (num == null) {
                    throw com.squareup.moshi.internal.b.k("status", "status", reader);
                }
            } else if (iK0 == 2) {
                str2 = (String) this.d.a(reader);
            }
        }
        reader.i();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("id", "id", reader);
        }
        if (num != null) {
            return new UniversalUploadFlowPracticeTestsStatus(str, num.intValue(), str2);
        }
        throw com.squareup.moshi.internal.b.e("status", "status", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        UniversalUploadFlowPracticeTestsStatus universalUploadFlowPracticeTestsStatus = (UniversalUploadFlowPracticeTestsStatus) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (universalUploadFlowPracticeTestsStatus == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, universalUploadFlowPracticeTestsStatus.a);
        writer.l("status");
        this.c.g(writer, Integer.valueOf(universalUploadFlowPracticeTestsStatus.b));
        writer.l("error");
        this.d.g(writer, universalUploadFlowPracticeTestsStatus.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(60, "GeneratedJsonAdapter(UniversalUploadFlowPracticeTestsStatus)", "toString(...)");
    }
}
