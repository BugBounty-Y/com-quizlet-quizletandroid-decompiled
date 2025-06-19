package com.quizlet.shared.models.api.eligibility;

import com.quizlet.shared.models.api.base.errors.QuizletApiError;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class UsersFeatureEligibilityResponse {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] c = {new C5048d(q0.a, 0), null};
    public final List a;
    public final QuizletApiError b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return UsersFeatureEligibilityResponse$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ UsersFeatureEligibilityResponse(int i, List list, QuizletApiError quizletApiError) {
        if ((i & 1) == 0) {
            this.a = null;
        } else {
            this.a = list;
        }
        if ((i & 2) == 0) {
            this.b = null;
        } else {
            this.b = quizletApiError;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UsersFeatureEligibilityResponse)) {
            return false;
        }
        UsersFeatureEligibilityResponse usersFeatureEligibilityResponse = (UsersFeatureEligibilityResponse) obj;
        return Intrinsics.b(this.a, usersFeatureEligibilityResponse.a) && Intrinsics.b(this.b, usersFeatureEligibilityResponse.b);
    }

    public final int hashCode() {
        List list = this.a;
        int iHashCode = (list == null ? 0 : list.hashCode()) * 31;
        QuizletApiError quizletApiError = this.b;
        return iHashCode + (quizletApiError != null ? quizletApiError.hashCode() : 0);
    }

    public final String toString() {
        return "UsersFeatureEligibilityResponse(features=" + this.a + ", error=" + this.b + ")";
    }
}
