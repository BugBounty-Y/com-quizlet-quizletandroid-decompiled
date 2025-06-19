package com.quizlet.remote.model.union.studysetwithcreator;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.search.RemoteSearchSocialSignalForSets;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.set.RemoteSetClassification;
import com.quizlet.remote.model.union.studysetwithcreator.StudySetsWithCreatorsAndClassificationsResponse;
import com.quizlet.remote.model.user.RemoteUser;
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
public final class StudySetsWithCreatorsAndClassificationsResponse_ModelsJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;

    public StudySetsWithCreatorsAndClassificationsResponse_ModelsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("set", "user", "setSubjectClassification", "socialProof");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, RemoteSet.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "sets");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, RemoteUser.class), m, "users");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, RemoteSetClassification.class), m, "classifications");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(H.f(List.class, RemoteSearchSocialSignalForSets.class), m, "socialSignalsForSets");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        List list2 = null;
        List list3 = null;
        List list4 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
            } else if (iK0 == 1) {
                list2 = (List) this.c.a(reader);
            } else if (iK0 == 2) {
                list3 = (List) this.d.a(reader);
            } else if (iK0 == 3) {
                list4 = (List) this.e.a(reader);
            }
        }
        reader.i();
        return new StudySetsWithCreatorsAndClassificationsResponse.Models(list, list2, list3, list4);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        StudySetsWithCreatorsAndClassificationsResponse.Models models = (StudySetsWithCreatorsAndClassificationsResponse.Models) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (models == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("set");
        this.b.g(writer, models.a);
        writer.l("user");
        this.c.g(writer, models.b);
        writer.l("setSubjectClassification");
        this.d.g(writer, models.c);
        writer.l("socialProof");
        this.e.g(writer, models.d);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(76, "GeneratedJsonAdapter(StudySetsWithCreatorsAndClassificationsResponse.Models)", "toString(...)");
    }
}
