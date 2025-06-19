package com.quizlet.remote.model.set;

import com.quizlet.remote.model.base.ApiResponse;
import com.quizlet.remote.model.user.RemoteUser;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RecommendedSetsBehaviorBasedResponse extends ApiResponse {
    public final RecommendedSetsBehaviorBasedModels d;
    public final RecommendedSetsBehaviorBasedSource e;

    @m(generateAdapter = true)
    @Metadata
    public static final class RecommendedSetsBehaviorBasedModels {
        public final List a;
        public final List b;

        public RecommendedSetsBehaviorBasedModels(@InterfaceC4853h(name = "user") List<RemoteUser> list, @InterfaceC4853h(name = "set") List<RemoteSet> list2) {
            this.a = list;
            this.b = list2;
        }

        @NotNull
        public final RecommendedSetsBehaviorBasedModels copy(@InterfaceC4853h(name = "user") List<RemoteUser> list, @InterfaceC4853h(name = "set") List<RemoteSet> list2) {
            return new RecommendedSetsBehaviorBasedModels(list, list2);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof RecommendedSetsBehaviorBasedModels)) {
                return false;
            }
            RecommendedSetsBehaviorBasedModels recommendedSetsBehaviorBasedModels = (RecommendedSetsBehaviorBasedModels) obj;
            return Intrinsics.b(this.a, recommendedSetsBehaviorBasedModels.a) && Intrinsics.b(this.b, recommendedSetsBehaviorBasedModels.b);
        }

        public final int hashCode() {
            List list = this.a;
            int iHashCode = (list == null ? 0 : list.hashCode()) * 31;
            List list2 = this.b;
            return iHashCode + (list2 != null ? list2.hashCode() : 0);
        }

        public final String toString() {
            return "RecommendedSetsBehaviorBasedModels(user=" + this.a + ", set=" + this.b + ")";
        }
    }

    @m(generateAdapter = true)
    @Metadata
    public static final class RecommendedSetsBehaviorBasedSource {
        public final RemoteUser a;
        public final RemoteSet b;

        public RecommendedSetsBehaviorBasedSource(@InterfaceC4853h(name = "user") RemoteUser remoteUser, RemoteSet remoteSet) {
            this.a = remoteUser;
            this.b = remoteSet;
        }

        @NotNull
        public final RecommendedSetsBehaviorBasedSource copy(@InterfaceC4853h(name = "user") RemoteUser remoteUser, RemoteSet remoteSet) {
            return new RecommendedSetsBehaviorBasedSource(remoteUser, remoteSet);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof RecommendedSetsBehaviorBasedSource)) {
                return false;
            }
            RecommendedSetsBehaviorBasedSource recommendedSetsBehaviorBasedSource = (RecommendedSetsBehaviorBasedSource) obj;
            return Intrinsics.b(this.a, recommendedSetsBehaviorBasedSource.a) && Intrinsics.b(this.b, recommendedSetsBehaviorBasedSource.b);
        }

        public final int hashCode() {
            RemoteUser remoteUser = this.a;
            int iHashCode = (remoteUser == null ? 0 : remoteUser.hashCode()) * 31;
            RemoteSet remoteSet = this.b;
            return iHashCode + (remoteSet != null ? remoteSet.hashCode() : 0);
        }

        public final String toString() {
            return "RecommendedSetsBehaviorBasedSource(user=" + this.a + ", set=" + this.b + ")";
        }
    }

    public RecommendedSetsBehaviorBasedResponse(@InterfaceC4853h(name = "models") RecommendedSetsBehaviorBasedModels recommendedSetsBehaviorBasedModels, RecommendedSetsBehaviorBasedSource recommendedSetsBehaviorBasedSource) {
        this.d = recommendedSetsBehaviorBasedModels;
        this.e = recommendedSetsBehaviorBasedSource;
    }

    @NotNull
    public final RecommendedSetsBehaviorBasedResponse copy(@InterfaceC4853h(name = "models") RecommendedSetsBehaviorBasedModels recommendedSetsBehaviorBasedModels, RecommendedSetsBehaviorBasedSource recommendedSetsBehaviorBasedSource) {
        return new RecommendedSetsBehaviorBasedResponse(recommendedSetsBehaviorBasedModels, recommendedSetsBehaviorBasedSource);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RecommendedSetsBehaviorBasedResponse)) {
            return false;
        }
        RecommendedSetsBehaviorBasedResponse recommendedSetsBehaviorBasedResponse = (RecommendedSetsBehaviorBasedResponse) obj;
        return Intrinsics.b(this.d, recommendedSetsBehaviorBasedResponse.d) && Intrinsics.b(this.e, recommendedSetsBehaviorBasedResponse.e);
    }

    public final int hashCode() {
        RecommendedSetsBehaviorBasedModels recommendedSetsBehaviorBasedModels = this.d;
        int iHashCode = (recommendedSetsBehaviorBasedModels == null ? 0 : recommendedSetsBehaviorBasedModels.hashCode()) * 31;
        RecommendedSetsBehaviorBasedSource recommendedSetsBehaviorBasedSource = this.e;
        return iHashCode + (recommendedSetsBehaviorBasedSource != null ? recommendedSetsBehaviorBasedSource.hashCode() : 0);
    }

    public final String toString() {
        return "RecommendedSetsBehaviorBasedResponse(models=" + this.d + ", source=" + this.e + ")";
    }
}
