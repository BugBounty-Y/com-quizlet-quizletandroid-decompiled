package com.quizlet.remote.model.set;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.set.IrrelevantRecommendationsResponse;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
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
public final class IrrelevantRecommendationsResponse_ModelsJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;

    public IrrelevantRecommendationsResponse_ModelsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("irrelevantRecommendation");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(H.f(List.class, RemoteIrrelevantRecommendation.class), M.a, "irrelevantRecommendation");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
            }
        }
        reader.i();
        return new IrrelevantRecommendationsResponse.Models(list);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        IrrelevantRecommendationsResponse.Models models = (IrrelevantRecommendationsResponse.Models) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (models == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("irrelevantRecommendation");
        this.b.g(writer, models.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(62, "GeneratedJsonAdapter(IrrelevantRecommendationsResponse.Models)", "toString(...)");
    }
}
