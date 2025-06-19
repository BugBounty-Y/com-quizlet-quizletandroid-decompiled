package com.quizlet.remote.model.course;

import com.quizlet.remote.model.base.ApiResponse;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteNewCourseMembershipResponse extends ApiResponse {
    public final CourseMembershipModelsResponse d;

    @m(generateAdapter = true)
    @Metadata
    public static final class CourseMembershipModelsResponse {
        public final List a;
        public final List b;

        public CourseMembershipModelsResponse(@InterfaceC4853h(name = "courseMembership") @NotNull List<RemoteNewCourseMembership> courseMembership, @InterfaceC4853h(name = "folder") List<RemoteFolder> list) {
            Intrinsics.checkNotNullParameter(courseMembership, "courseMembership");
            this.a = courseMembership;
            this.b = list;
        }

        @NotNull
        public final CourseMembershipModelsResponse copy(@InterfaceC4853h(name = "courseMembership") @NotNull List<RemoteNewCourseMembership> courseMembership, @InterfaceC4853h(name = "folder") List<RemoteFolder> list) {
            Intrinsics.checkNotNullParameter(courseMembership, "courseMembership");
            return new CourseMembershipModelsResponse(courseMembership, list);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof CourseMembershipModelsResponse)) {
                return false;
            }
            CourseMembershipModelsResponse courseMembershipModelsResponse = (CourseMembershipModelsResponse) obj;
            return Intrinsics.b(this.a, courseMembershipModelsResponse.a) && Intrinsics.b(this.b, courseMembershipModelsResponse.b);
        }

        public final int hashCode() {
            int iHashCode = this.a.hashCode() * 31;
            List list = this.b;
            return iHashCode + (list == null ? 0 : list.hashCode());
        }

        public final String toString() {
            return "CourseMembershipModelsResponse(courseMembership=" + this.a + ", folder=" + this.b + ")";
        }
    }

    public RemoteNewCourseMembershipResponse(@InterfaceC4853h(name = "models") @NotNull CourseMembershipModelsResponse models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    @NotNull
    public final RemoteNewCourseMembershipResponse copy(@InterfaceC4853h(name = "models") @NotNull CourseMembershipModelsResponse models) {
        Intrinsics.checkNotNullParameter(models, "models");
        return new RemoteNewCourseMembershipResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteNewCourseMembershipResponse) && Intrinsics.b(this.d, ((RemoteNewCourseMembershipResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.hashCode();
    }

    public final String toString() {
        return "RemoteNewCourseMembershipResponse(models=" + this.d + ")";
    }
}
