package com.quizlet.remote.model.union.studysetwithcreatorinclass;

import com.quizlet.remote.model.base.ApiResponse;
import com.quizlet.remote.model.classset.RemoteClassSet;
import com.quizlet.remote.model.set.RemoteSet;
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
public final class StudySetWithCreatorInClassResponse extends ApiResponse {
    public final Models d;

    @m(generateAdapter = true)
    @Metadata
    public static final class Models {
        public final List a;
        public final List b;
        public final List c;

        public Models(@InterfaceC4853h(name = "classSet") List<RemoteClassSet> list, @InterfaceC4853h(name = "set") List<RemoteSet> list2, @InterfaceC4853h(name = "user") List<RemoteUser> list3) {
            this.a = list;
            this.b = list2;
            this.c = list3;
        }

        @NotNull
        public final Models copy(@InterfaceC4853h(name = "classSet") List<RemoteClassSet> list, @InterfaceC4853h(name = "set") List<RemoteSet> list2, @InterfaceC4853h(name = "user") List<RemoteUser> list3) {
            return new Models(list, list2, list3);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Models)) {
                return false;
            }
            Models models = (Models) obj;
            return Intrinsics.b(this.a, models.a) && Intrinsics.b(this.b, models.b) && Intrinsics.b(this.c, models.c);
        }

        public final int hashCode() {
            List list = this.a;
            int iHashCode = (list == null ? 0 : list.hashCode()) * 31;
            List list2 = this.b;
            int iHashCode2 = (iHashCode + (list2 == null ? 0 : list2.hashCode())) * 31;
            List list3 = this.c;
            return iHashCode2 + (list3 != null ? list3.hashCode() : 0);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("Models(classSets=");
            sb.append(this.a);
            sb.append(", studySets=");
            sb.append(this.b);
            sb.append(", users=");
            return android.support.v4.media.session.a.n(")", sb, this.c);
        }
    }

    public StudySetWithCreatorInClassResponse(@InterfaceC4853h(name = "models") Models models) {
        this.d = models;
    }

    @NotNull
    public final StudySetWithCreatorInClassResponse copy(@InterfaceC4853h(name = "models") Models models) {
        return new StudySetWithCreatorInClassResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof StudySetWithCreatorInClassResponse) && Intrinsics.b(this.d, ((StudySetWithCreatorInClassResponse) obj).d);
    }

    public final int hashCode() {
        Models models = this.d;
        if (models == null) {
            return 0;
        }
        return models.hashCode();
    }

    public final String toString() {
        return "StudySetWithCreatorInClassResponse(models=" + this.d + ")";
    }
}
