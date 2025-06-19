package com.quizlet.remote.model.set;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.set.RecommendedSetsBehaviorBasedResponse;
import com.quizlet.remote.model.user.RemoteUser;
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
public final class RecommendedSetsBehaviorBasedResponse_RecommendedSetsBehaviorBasedSourceJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;

    public RecommendedSetsBehaviorBasedResponse_RecommendedSetsBehaviorBasedSourceJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("user", "set");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(RemoteUser.class, m, "user");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(RemoteSet.class, m, "set");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        RemoteUser remoteUser = null;
        RemoteSet remoteSet = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                remoteUser = (RemoteUser) this.b.a(reader);
            } else if (iK0 == 1) {
                remoteSet = (RemoteSet) this.c.a(reader);
            }
        }
        reader.i();
        return new RecommendedSetsBehaviorBasedResponse.RecommendedSetsBehaviorBasedSource(remoteUser, remoteSet);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RecommendedSetsBehaviorBasedResponse.RecommendedSetsBehaviorBasedSource recommendedSetsBehaviorBasedSource = (RecommendedSetsBehaviorBasedResponse.RecommendedSetsBehaviorBasedSource) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (recommendedSetsBehaviorBasedSource == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("user");
        this.b.g(writer, recommendedSetsBehaviorBasedSource.a);
        writer.l("set");
        this.c.g(writer, recommendedSetsBehaviorBasedSource.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(93, "GeneratedJsonAdapter(RecommendedSetsBehaviorBasedResponse.RecommendedSetsBehaviorBasedSource)", "toString(...)");
    }
}
