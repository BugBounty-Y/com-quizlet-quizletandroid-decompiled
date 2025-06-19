package com.quizlet.remote.model.school;

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
public final class RemoteSchoolResponse extends ApiResponse {
    public final SchoolModelsResponse d;

    @m(generateAdapter = true)
    @Metadata
    public static final class SchoolModelsResponse {
        public final List a;

        public SchoolModelsResponse(@InterfaceC4853h(name = "school") @NotNull List<RemoteSchool> school) {
            Intrinsics.checkNotNullParameter(school, "school");
            this.a = school;
        }

        @NotNull
        public final SchoolModelsResponse copy(@InterfaceC4853h(name = "school") @NotNull List<RemoteSchool> school) {
            Intrinsics.checkNotNullParameter(school, "school");
            return new SchoolModelsResponse(school);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof SchoolModelsResponse) && Intrinsics.b(this.a, ((SchoolModelsResponse) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.n(")", new StringBuilder("SchoolModelsResponse(school="), this.a);
        }
    }

    public RemoteSchoolResponse(@InterfaceC4853h(name = "models") @NotNull SchoolModelsResponse models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    @NotNull
    public final RemoteSchoolResponse copy(@InterfaceC4853h(name = "models") @NotNull SchoolModelsResponse models) {
        Intrinsics.checkNotNullParameter(models, "models");
        return new RemoteSchoolResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteSchoolResponse) && Intrinsics.b(this.d, ((RemoteSchoolResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "RemoteSchoolResponse(models=" + this.d + ")";
    }
}
