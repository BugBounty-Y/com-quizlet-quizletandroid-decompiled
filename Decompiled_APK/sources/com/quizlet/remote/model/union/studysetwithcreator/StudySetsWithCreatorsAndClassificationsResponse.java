package com.quizlet.remote.model.union.studysetwithcreator;

import com.quizlet.remote.model.base.ApiResponse;
import com.quizlet.remote.model.search.RemoteSearchSocialSignalForSets;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.set.RemoteSetClassification;
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
public final class StudySetsWithCreatorsAndClassificationsResponse extends ApiResponse {
    public final Models d;

    @m(generateAdapter = true)
    @Metadata
    public static final class Models {
        public final List a;
        public final List b;
        public final List c;
        public final List d;

        public Models(@InterfaceC4853h(name = "set") List<RemoteSet> list, @InterfaceC4853h(name = "user") List<RemoteUser> list2, @InterfaceC4853h(name = "setSubjectClassification") List<RemoteSetClassification> list3, @InterfaceC4853h(name = "socialProof") List<RemoteSearchSocialSignalForSets> list4) {
            this.a = list;
            this.b = list2;
            this.c = list3;
            this.d = list4;
        }

        @NotNull
        public final Models copy(@InterfaceC4853h(name = "set") List<RemoteSet> list, @InterfaceC4853h(name = "user") List<RemoteUser> list2, @InterfaceC4853h(name = "setSubjectClassification") List<RemoteSetClassification> list3, @InterfaceC4853h(name = "socialProof") List<RemoteSearchSocialSignalForSets> list4) {
            return new Models(list, list2, list3, list4);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Models)) {
                return false;
            }
            Models models = (Models) obj;
            return Intrinsics.b(this.a, models.a) && Intrinsics.b(this.b, models.b) && Intrinsics.b(this.c, models.c) && Intrinsics.b(this.d, models.d);
        }

        public final int hashCode() {
            List list = this.a;
            int iHashCode = (list == null ? 0 : list.hashCode()) * 31;
            List list2 = this.b;
            int iHashCode2 = (iHashCode + (list2 == null ? 0 : list2.hashCode())) * 31;
            List list3 = this.c;
            int iHashCode3 = (iHashCode2 + (list3 == null ? 0 : list3.hashCode())) * 31;
            List list4 = this.d;
            return iHashCode3 + (list4 != null ? list4.hashCode() : 0);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("Models(sets=");
            sb.append(this.a);
            sb.append(", users=");
            sb.append(this.b);
            sb.append(", classifications=");
            sb.append(this.c);
            sb.append(", socialSignalsForSets=");
            return android.support.v4.media.session.a.n(")", sb, this.d);
        }
    }

    public StudySetsWithCreatorsAndClassificationsResponse(@InterfaceC4853h(name = "models") Models models) {
        this.d = models;
    }

    @NotNull
    public final StudySetsWithCreatorsAndClassificationsResponse copy(@InterfaceC4853h(name = "models") Models models) {
        return new StudySetsWithCreatorsAndClassificationsResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof StudySetsWithCreatorsAndClassificationsResponse) && Intrinsics.b(this.d, ((StudySetsWithCreatorsAndClassificationsResponse) obj).d);
    }

    public final int hashCode() {
        Models models = this.d;
        if (models == null) {
            return 0;
        }
        return models.hashCode();
    }

    public final String toString() {
        return "StudySetsWithCreatorsAndClassificationsResponse(models=" + this.d + ")";
    }
}
