package com.quizlet.remote.model.school.memberships;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSchoolMembershipResponse extends ApiResponse {
    public final SchoolMembershipModels d;

    @m(generateAdapter = true)
    @Metadata
    public static final class SchoolMembershipModels {
        public final List a;

        public SchoolMembershipModels(@InterfaceC4853h(name = "schoolMembership") @NotNull List<RemoteSchoolMembership> schoolMembership) {
            Intrinsics.checkNotNullParameter(schoolMembership, "schoolMembership");
            this.a = schoolMembership;
        }

        @NotNull
        public final SchoolMembershipModels copy(@InterfaceC4853h(name = "schoolMembership") @NotNull List<RemoteSchoolMembership> schoolMembership) {
            Intrinsics.checkNotNullParameter(schoolMembership, "schoolMembership");
            return new SchoolMembershipModels(schoolMembership);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof SchoolMembershipModels) && Intrinsics.b(this.a, ((SchoolMembershipModels) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.n(")", new StringBuilder("SchoolMembershipModels(schoolMembership="), this.a);
        }
    }

    public RemoteSchoolMembershipResponse(@InterfaceC4853h(name = "models") @NotNull SchoolMembershipModels models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    @NotNull
    public final RemoteSchoolMembershipResponse copy(@InterfaceC4853h(name = "models") @NotNull SchoolMembershipModels models) {
        Intrinsics.checkNotNullParameter(models, "models");
        return new RemoteSchoolMembershipResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteSchoolMembershipResponse) && Intrinsics.b(this.d, ((RemoteSchoolMembershipResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "RemoteSchoolMembershipResponse(models=" + this.d + ")";
    }
}
