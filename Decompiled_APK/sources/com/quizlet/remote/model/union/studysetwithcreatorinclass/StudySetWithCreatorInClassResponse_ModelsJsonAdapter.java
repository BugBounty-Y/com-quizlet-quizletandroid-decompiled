package com.quizlet.remote.model.union.studysetwithcreatorinclass;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.classset.RemoteClassSet;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.union.studysetwithcreatorinclass.StudySetWithCreatorInClassResponse;
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
public final class StudySetWithCreatorInClassResponse_ModelsJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;

    public StudySetWithCreatorInClassResponse_ModelsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("classSet", "set", "user");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, RemoteClassSet.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "classSets");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, RemoteSet.class), m, "studySets");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, RemoteUser.class), m, "users");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        List list2 = null;
        List list3 = null;
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
            }
        }
        reader.i();
        return new StudySetWithCreatorInClassResponse.Models(list, list2, list3);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        StudySetWithCreatorInClassResponse.Models models = (StudySetWithCreatorInClassResponse.Models) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (models == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("classSet");
        this.b.g(writer, models.a);
        writer.l("set");
        this.c.g(writer, models.b);
        writer.l("user");
        this.d.g(writer, models.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(63, "GeneratedJsonAdapter(StudySetWithCreatorInClassResponse.Models)", "toString(...)");
    }
}
