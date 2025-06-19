package com.quizlet.remote.model.search;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.school.RemoteSchool;
import com.quizlet.remote.model.set.RemoteSet;
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
public final class RemoteAllResultsAssociationModelsJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;

    public RemoteAllResultsAssociationModelsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("school", "user", "set");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, RemoteSchool.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "schools");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, RemoteUser.class), m, "setsCreators");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, RemoteSet.class), m, "termSets");
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
        return new RemoteAllResultsAssociationModels(list, list2, list3);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteAllResultsAssociationModels remoteAllResultsAssociationModels = (RemoteAllResultsAssociationModels) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteAllResultsAssociationModels == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("school");
        this.b.g(writer, remoteAllResultsAssociationModels.a);
        writer.l("user");
        this.c.g(writer, remoteAllResultsAssociationModels.b);
        writer.l("set");
        this.d.g(writer, remoteAllResultsAssociationModels.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(55, "GeneratedJsonAdapter(RemoteAllResultsAssociationModels)", "toString(...)");
    }
}
