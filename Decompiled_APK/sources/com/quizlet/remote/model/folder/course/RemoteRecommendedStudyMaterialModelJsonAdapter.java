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
public final class RemoteRecommendedStudyMaterialModelJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;

    public RemoteRecommendedStudyMaterialModelJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("id", "studyMaterialType", "studyMaterialId", "rank", "socialProof");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Integer.class, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "studyMaterialId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(RemoteRecommendedStudyMaterialModel.SocialProof.class, m, "socialProof");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Integer num = null;
        Integer num2 = null;
        String str = null;
        Integer num3 = null;
        RemoteRecommendedStudyMaterialModel.SocialProof socialProof = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    num = (Integer) lVar.a(reader);
                } else if (iK0 == 1) {
                    num2 = (Integer) lVar.a(reader);
                } else if (iK0 == 2) {
                    str = (String) this.c.a(reader);
                } else if (iK0 == 3) {
                    num3 = (Integer) lVar.a(reader);
                } else if (iK0 == 4) {
                    socialProof = (RemoteRecommendedStudyMaterialModel.SocialProof) this.d.a(reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        return new RemoteRecommendedStudyMaterialModel(num, num2, str, num3, socialProof);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteRecommendedStudyMaterialModel remoteRecommendedStudyMaterialModel = (RemoteRecommendedStudyMaterialModel) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteRecommendedStudyMaterialModel == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        l lVar = this.b;
        lVar.g(writer, remoteRecommendedStudyMaterialModel.a);
        writer.l("studyMaterialType");
        lVar.g(writer, remoteRecommendedStudyMaterialModel.b);
        writer.l("studyMaterialId");
        this.c.g(writer, remoteRecommendedStudyMaterialModel.c);
        writer.l("rank");
        lVar.g(writer, remoteRecommendedStudyMaterialModel.d);
        writer.l("socialProof");
        this.d.g(writer, remoteRecommendedStudyMaterialModel.e);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(57, "GeneratedJsonAdapter(RemoteRecommendedStudyMaterialModel)", "toString(...)");
    }
}
