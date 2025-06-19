package com.quizlet.remote.model.explanations.exercise;

import com.quizlet.remote.model.base.ApiResponse;
import com.quizlet.remote.model.metering.RemoteMeteringInfo;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class ExerciseDetailsResponse extends ApiResponse {
    public final Models d;
    public final RemoteMeteringInfo e;
    public final Boolean f;

    @m(generateAdapter = true)
    @Metadata
    public static final class Models {
        public final List a;

        public Models(@InterfaceC4853h(name = "textbookExercise") List<RemoteExerciseDetails> list) {
            this.a = list;
        }

        @NotNull
        public final Models copy(@InterfaceC4853h(name = "textbookExercise") List<RemoteExerciseDetails> list) {
            return new Models(list);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Models) && Intrinsics.b(this.a, ((Models) obj).a);
        }

        public final int hashCode() {
            List list = this.a;
            if (list == null) {
                return 0;
            }
            return list.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.n(")", new StringBuilder("Models(exerciseDetails="), this.a);
        }
    }

    public ExerciseDetailsResponse(@InterfaceC4853h(name = "models") Models models, @InterfaceC4853h(name = "metering") RemoteMeteringInfo remoteMeteringInfo, @InterfaceC4853h(name = "isContentLimited") Boolean bool) {
        this.d = models;
        this.e = remoteMeteringInfo;
        this.f = bool;
    }

    @NotNull
    public final ExerciseDetailsResponse copy(@InterfaceC4853h(name = "models") Models models, @InterfaceC4853h(name = "metering") RemoteMeteringInfo remoteMeteringInfo, @InterfaceC4853h(name = "isContentLimited") Boolean bool) {
        return new ExerciseDetailsResponse(models, remoteMeteringInfo, bool);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ExerciseDetailsResponse)) {
            return false;
        }
        ExerciseDetailsResponse exerciseDetailsResponse = (ExerciseDetailsResponse) obj;
        return Intrinsics.b(this.d, exerciseDetailsResponse.d) && Intrinsics.b(this.e, exerciseDetailsResponse.e) && Intrinsics.b(this.f, exerciseDetailsResponse.f);
    }

    public final int hashCode() {
        Models models = this.d;
        int iHashCode = (models == null ? 0 : models.hashCode()) * 31;
        RemoteMeteringInfo remoteMeteringInfo = this.e;
        int iHashCode2 = (iHashCode + (remoteMeteringInfo == null ? 0 : remoteMeteringInfo.hashCode())) * 31;
        Boolean bool = this.f;
        return iHashCode2 + (bool != null ? bool.hashCode() : 0);
    }

    public final String toString() {
        return "ExerciseDetailsResponse(models=" + this.d + ", meteringInfo=" + this.e + ", isContentLimited=" + this.f + ")";
    }
}
