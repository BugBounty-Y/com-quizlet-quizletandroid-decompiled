package com.quizlet.remote.model.course;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.course.RemoteNewCourseMembershipResponse;
import com.quizlet.remote.model.folder.RemoteFolder;
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
public final class RemoteNewCourseMembershipResponse_CourseMembershipModelsResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;

    public RemoteNewCourseMembershipResponse_CourseMembershipModelsResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("courseMembership", "folder");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, RemoteNewCourseMembership.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "courseMembership");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, RemoteFolder.class), m, "folder");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        List list2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
                if (list == null) {
                    throw com.squareup.moshi.internal.b.k("courseMembership", "courseMembership", reader);
                }
            } else if (iK0 == 1) {
                list2 = (List) this.c.a(reader);
            }
        }
        reader.i();
        if (list != null) {
            return new RemoteNewCourseMembershipResponse.CourseMembershipModelsResponse(list, list2);
        }
        throw com.squareup.moshi.internal.b.e("courseMembership", "courseMembership", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteNewCourseMembershipResponse.CourseMembershipModelsResponse courseMembershipModelsResponse = (RemoteNewCourseMembershipResponse.CourseMembershipModelsResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (courseMembershipModelsResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("courseMembership");
        this.b.g(writer, courseMembershipModelsResponse.a);
        writer.l("folder");
        this.c.g(writer, courseMembershipModelsResponse.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(86, "GeneratedJsonAdapter(RemoteNewCourseMembershipResponse.CourseMembershipModelsResponse)", "toString(...)");
    }
}
