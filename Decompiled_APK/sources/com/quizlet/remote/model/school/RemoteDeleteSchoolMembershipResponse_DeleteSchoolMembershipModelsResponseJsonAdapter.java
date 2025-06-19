package com.quizlet.remote.model.school;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.school.RemoteDeleteSchoolMembershipResponse;
import com.quizlet.remote.model.school.memberships.RemoteDeleteSchoolMembership;
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
public final class RemoteDeleteSchoolMembershipResponse_DeleteSchoolMembershipModelsResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;

    public RemoteDeleteSchoolMembershipResponse_DeleteSchoolMembershipModelsResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("schoolMembership");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(H.f(List.class, RemoteDeleteSchoolMembership.class), M.a, "schoolMembership");
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
                throw com.squareup.moshi.internal.b.k("schoolMembership", "schoolMembership", reader);
            }
        }
        reader.i();
        if (list != null) {
            return new RemoteDeleteSchoolMembershipResponse.DeleteSchoolMembershipModelsResponse(list);
        }
        throw com.squareup.moshi.internal.b.e("schoolMembership", "schoolMembership", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteDeleteSchoolMembershipResponse.DeleteSchoolMembershipModelsResponse deleteSchoolMembershipModelsResponse = (RemoteDeleteSchoolMembershipResponse.DeleteSchoolMembershipModelsResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (deleteSchoolMembershipModelsResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("schoolMembership");
        this.b.g(writer, deleteSchoolMembershipModelsResponse.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(95, "GeneratedJsonAdapter(RemoteDeleteSchoolMembershipResponse.DeleteSchoolMembershipModelsResponse)", "toString(...)");
    }
}
