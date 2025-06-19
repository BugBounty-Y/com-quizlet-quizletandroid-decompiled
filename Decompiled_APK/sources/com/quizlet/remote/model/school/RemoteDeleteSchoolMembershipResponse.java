package com.quizlet.remote.model.school;

import com.quizlet.remote.model.base.ApiResponse;
import com.quizlet.remote.model.school.memberships.RemoteDeleteSchoolMembership;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteDeleteSchoolMembershipResponse extends ApiResponse {
    public final DeleteSchoolMembershipModelsResponse d;

    @m(generateAdapter = true)
    @Metadata
    public static final class DeleteSchoolMembershipModelsResponse {
        public final List a;

        public DeleteSchoolMembershipModelsResponse(@InterfaceC4853h(name = "schoolMembership") @NotNull List<RemoteDeleteSchoolMembership> schoolMembership) {
            Intrinsics.checkNotNullParameter(schoolMembership, "schoolMembership");
            this.a = schoolMembership;
        }

        @NotNull
        public final DeleteSchoolMembershipModelsResponse copy(@InterfaceC4853h(name = "schoolMembership") @NotNull List<RemoteDeleteSchoolMembership> schoolMembership) {
            Intrinsics.checkNotNullParameter(schoolMembership, "schoolMembership");
            return new DeleteSchoolMembershipModelsResponse(schoolMembership);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof DeleteSchoolMembershipModelsResponse) && Intrinsics.b(this.a, ((DeleteSchoolMembershipModelsResponse) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.n(")", new StringBuilder("DeleteSchoolMembershipModelsResponse(schoolMembership="), this.a);
        }
    }

    public RemoteDeleteSchoolMembershipResponse(@InterfaceC4853h(name = "models") @NotNull DeleteSchoolMembershipModelsResponse models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    @NotNull
    public final RemoteDeleteSchoolMembershipResponse copy(@InterfaceC4853h(name = "models") @NotNull DeleteSchoolMembershipModelsResponse models) {
        Intrinsics.checkNotNullParameter(models, "models");
        return new RemoteDeleteSchoolMembershipResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteDeleteSchoolMembershipResponse) && Intrinsics.b(this.d, ((RemoteDeleteSchoolMembershipResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "RemoteDeleteSchoolMembershipResponse(models=" + this.d + ")";
    }
}
