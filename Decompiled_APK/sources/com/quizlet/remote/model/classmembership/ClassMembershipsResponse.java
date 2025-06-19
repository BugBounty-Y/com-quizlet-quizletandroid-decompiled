package com.quizlet.remote.model.classmembership;

import com.quizlet.db.data.models.base.AssociationNames;
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
public final class ClassMembershipsResponse extends ApiResponse {
    public final Models d;

    @m(generateAdapter = true)
    @Metadata
    public static final class Models {
        public final List a;

        public Models(@InterfaceC4853h(name = AssociationNames.CLASS_MEMBERSHIP) @NotNull List<RemoteClassMembership> classMemberships) {
            Intrinsics.checkNotNullParameter(classMemberships, "classMemberships");
            this.a = classMemberships;
        }

        @NotNull
        public final Models copy(@InterfaceC4853h(name = AssociationNames.CLASS_MEMBERSHIP) @NotNull List<RemoteClassMembership> classMemberships) {
            Intrinsics.checkNotNullParameter(classMemberships, "classMemberships");
            return new Models(classMemberships);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Models) && Intrinsics.b(this.a, ((Models) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.n(")", new StringBuilder("Models(classMemberships="), this.a);
        }
    }

    public ClassMembershipsResponse(@InterfaceC4853h(name = "models") @NotNull Models models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    @NotNull
    public final ClassMembershipsResponse copy(@InterfaceC4853h(name = "models") @NotNull Models models) {
        Intrinsics.checkNotNullParameter(models, "models");
        return new ClassMembershipsResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof ClassMembershipsResponse) && Intrinsics.b(this.d, ((ClassMembershipsResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "ClassMembershipsResponse(models=" + this.d + ")";
    }
}
