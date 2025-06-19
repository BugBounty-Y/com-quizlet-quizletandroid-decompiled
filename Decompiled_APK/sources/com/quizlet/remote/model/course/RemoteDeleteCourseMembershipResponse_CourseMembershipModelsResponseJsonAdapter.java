package com.quizlet.remote.model.course;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.course.RemoteDeleteCourseMembershipResponse;
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
public final class RemoteDeleteCourseMembershipResponse_CourseMembershipModelsResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;

    public RemoteDeleteCourseMembershipResponse_CourseMembershipModelsResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("courseMembership");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(H.f(List.class, RemoteDeleteCourseMembership.class), M.a, "courseMembership");
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
            } else if (iK0 == 0 && (list = (List) this.b.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("courseMembership", "courseMembership", reader);
            }
        }
        reader.i();
        if (list != null) {
            return new RemoteDeleteCourseMembershipResponse.CourseMembershipModelsResponse(list);
        }
        throw com.squareup.moshi.internal.b.e("courseMembership", "courseMembership", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteDeleteCourseMembershipResponse.CourseMembershipModelsResponse courseMembershipModelsResponse = (RemoteDeleteCourseMembershipResponse.CourseMembershipModelsResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (courseMembershipModelsResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("courseMembership");
        this.b.g(writer, courseMembershipModelsResponse.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(89, "GeneratedJsonAdapter(RemoteDeleteCourseMembershipResponse.CourseMembershipModelsResponse)", "toString(...)");
    }
}
