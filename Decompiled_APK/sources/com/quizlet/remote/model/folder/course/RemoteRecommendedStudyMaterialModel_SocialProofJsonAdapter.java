package com.quizlet.remote.model.folder.course;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.folder.course.RemoteRecommendedStudyMaterialModel;
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
public final class RemoteRecommendedStudyMaterialModel_SocialProofJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public RemoteRecommendedStudyMaterialModel_SocialProofJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("actionType", "userCount", "lastStudied");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "actionType");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.class, m, "userCount");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
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
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    str = (String) lVar.a(reader);
                } else if (iK0 == 1) {
                    num = (Integer) this.c.a(reader);
                } else if (iK0 == 2) {
                    str2 = (String) lVar.a(reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        return new RemoteRecommendedStudyMaterialModel.SocialProof(str, num, str2);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteRecommendedStudyMaterialModel.SocialProof socialProof = (RemoteRecommendedStudyMaterialModel.SocialProof) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (socialProof == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("actionType");
        l lVar = this.b;
        lVar.g(writer, socialProof.a);
        writer.l("userCount");
        this.c.g(writer, socialProof.b);
        writer.l("lastStudied");
        lVar.g(writer, socialProof.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(69, "GeneratedJsonAdapter(RemoteRecommendedStudyMaterialModel.SocialProof)", "toString(...)");
    }
}
