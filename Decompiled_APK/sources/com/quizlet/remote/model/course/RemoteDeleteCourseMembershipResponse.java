package com.quizlet.remote.model.course;

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
public final class RemoteDeleteCourseMembershipResponse extends ApiResponse {
    public final CourseMembershipModelsResponse d;

    @m(generateAdapter = true)
    @Metadata
    public static final class CourseMembershipModelsResponse {
        public final List a;

        public CourseMembershipModelsResponse(@InterfaceC4853h(name = "courseMembership") @NotNull List<RemoteDeleteCourseMembership> courseMembership) {
            Intrinsics.checkNotNullParameter(courseMembership, "courseMembership");
            this.a = courseMembership;
        }

        @NotNull
        public final CourseMembershipModelsResponse copy(@InterfaceC4853h(name = "courseMembership") @NotNull List<RemoteDeleteCourseMembership> courseMembership) {
            Intrinsics.checkNotNullParameter(courseMembership, "courseMembership");
            return new CourseMembershipModelsResponse(courseMembership);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof CourseMembershipModelsResponse) && Intrinsics.b(this.a, ((CourseMembershipModelsResponse) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.n(")", new StringBuilder("CourseMembershipModelsResponse(courseMembership="), this.a);
        }
    }

    public RemoteDeleteCourseMembershipResponse(@InterfaceC4853h(name = "models") @NotNull CourseMembershipModelsResponse models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    @NotNull
    public final RemoteDeleteCourseMembershipResponse copy(@InterfaceC4853h(name = "models") @NotNull CourseMembershipModelsResponse models) {
        Intrinsics.checkNotNullParameter(models, "models");
        return new RemoteDeleteCourseMembershipResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteDeleteCourseMembershipResponse) && Intrinsics.b(this.d, ((RemoteDeleteCourseMembershipResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "RemoteDeleteCourseMembershipResponse(models=" + this.d + ")";
    }
}
