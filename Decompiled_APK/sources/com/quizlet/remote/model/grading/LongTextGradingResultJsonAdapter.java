package com.quizlet.remote.model.grading;

import com.airbnb.lottie.parser.moshi.c;
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
public final class LongTextGradingResultJsonAdapter extends l {
    public final c a;
    public final l b;

    public LongTextGradingResultJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("longtextGradingResult");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(RemoteLongTextGradingResult.class, M.a, "longTextGradingResult");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        RemoteLongTextGradingResult remoteLongTextGradingResult = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                remoteLongTextGradingResult = (RemoteLongTextGradingResult) this.b.a(reader);
            }
        }
        reader.i();
        return new LongTextGradingResult(remoteLongTextGradingResult);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        LongTextGradingResult longTextGradingResult = (LongTextGradingResult) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (longTextGradingResult == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("longtextGradingResult");
        this.b.g(writer, longTextGradingResult.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(43, "GeneratedJsonAdapter(LongTextGradingResult)", "toString(...)");
    }
}
