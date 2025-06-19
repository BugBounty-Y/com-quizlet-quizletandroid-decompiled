package com.quizlet.remote.model.school.memberships;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class SchoolMembershipResponse extends ApiResponse {
    public final SchoolMembershipModels d;

    @m(generateAdapter = true)
    @Metadata
    public static final class SchoolMembershipModels {
        public final List a;
        public final List b;

        public SchoolMembershipModels(List school, List schoolMembership) {
            Intrinsics.checkNotNullParameter(school, "school");
            Intrinsics.checkNotNullParameter(schoolMembership, "schoolMembership");
            this.a = school;
            this.b = schoolMembership;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof SchoolMembershipModels)) {
                return false;
            }
            SchoolMembershipModels schoolMembershipModels = (SchoolMembershipModels) obj;
            return Intrinsics.b(this.a, schoolMembershipModels.a) && Intrinsics.b(this.b, schoolMembershipModels.b);
        }

        public final int hashCode() {
            return this.b.hashCode() + (this.a.hashCode() * 31);
        }

        public final String toString() {
            return "SchoolMembershipModels(school=" + this.a + ", schoolMembership=" + this.b + ")";
        }
    }

    public SchoolMembershipResponse(SchoolMembershipModels models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof SchoolMembershipResponse) && Intrinsics.b(this.d, ((SchoolMembershipResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.hashCode();
    }

    public final String toString() {
        return "SchoolMembershipResponse(models=" + this.d + ")";
    }
}
