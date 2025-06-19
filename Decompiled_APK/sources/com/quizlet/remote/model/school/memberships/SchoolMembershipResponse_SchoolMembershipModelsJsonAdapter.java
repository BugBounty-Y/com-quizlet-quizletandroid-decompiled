package com.quizlet.remote.model.school.memberships;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.school.RemoteSchool;
import com.quizlet.remote.model.school.memberships.SchoolMembershipResponse;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
import com.squareup.moshi.internal.b;
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
public final class SchoolMembershipResponse_SchoolMembershipModelsJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public SchoolMembershipResponse_SchoolMembershipModelsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("school", "schoolMembership");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, RemoteSchool.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "school");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, RemoteSchoolMembership.class), m, "schoolMembership");
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
                    throw b.k("school", "school", reader);
                }
            } else if (iK0 == 1 && (list2 = (List) this.c.a(reader)) == null) {
                throw b.k("schoolMembership", "schoolMembership", reader);
            }
        }
        reader.i();
        if (list == null) {
            throw b.e("school", "school", reader);
        }
        if (list2 != null) {
            return new SchoolMembershipResponse.SchoolMembershipModels(list, list2);
        }
        throw b.e("schoolMembership", "schoolMembership", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SchoolMembershipResponse.SchoolMembershipModels schoolMembershipModels = (SchoolMembershipResponse.SchoolMembershipModels) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (schoolMembershipModels == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("school");
        this.b.g(writer, schoolMembershipModels.a);
        writer.l("schoolMembership");
        this.c.g(writer, schoolMembershipModels.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(69, "GeneratedJsonAdapter(SchoolMembershipResponse.SchoolMembershipModels)", "toString(...)");
    }
}
