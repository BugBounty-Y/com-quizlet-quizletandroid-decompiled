package com.quizlet.remote.model.union.folderwithcreator;

import com.quizlet.remote.model.base.ApiResponse;
import com.quizlet.remote.model.course.RemoteCourse;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.school.RemoteSchool;
import com.quizlet.remote.model.user.RemoteUser;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class FolderWithCreatorResponse extends ApiResponse {
    public final Models d;

    public FolderWithCreatorResponse(@InterfaceC4853h(name = "models") Models models) {
        this.d = models;
    }

    @NotNull
    public final FolderWithCreatorResponse copy(@InterfaceC4853h(name = "models") Models models) {
        return new FolderWithCreatorResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FolderWithCreatorResponse) && Intrinsics.b(this.d, ((FolderWithCreatorResponse) obj).d);
    }

    public final int hashCode() {
        Models models = this.d;
        if (models == null) {
            return 0;
        }
        return models.hashCode();
    }

    public final String toString() {
        return "FolderWithCreatorResponse(models=" + this.d + ")";
    }

    @m(generateAdapter = true)
    @Metadata
    public static final class Models {
        public final List a;
        public final List b;
        public final List c;
        public final List d;

        public Models(@InterfaceC4853h(name = "folder") List<RemoteFolder> list, @InterfaceC4853h(name = "user") List<RemoteUser> list2, @InterfaceC4853h(name = "course") List<RemoteCourse> list3, @InterfaceC4853h(name = "school") List<RemoteSchool> list4) {
            this.a = list;
            this.b = list2;
            this.c = list3;
            this.d = list4;
        }

        @NotNull
        public final Models copy(@InterfaceC4853h(name = "folder") List<RemoteFolder> list, @InterfaceC4853h(name = "user") List<RemoteUser> list2, @InterfaceC4853h(name = "course") List<RemoteCourse> list3, @InterfaceC4853h(name = "school") List<RemoteSchool> list4) {
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
            StringBuilder sb = new StringBuilder("Models(folder=");
            sb.append(this.a);
            sb.append(", user=");
            sb.append(this.b);
            sb.append(", course=");
            sb.append(this.c);
            sb.append(", school=");
            return android.support.v4.media.session.a.n(")", sb, this.d);
        }

        public /* synthetic */ Models(List list, List list2, List list3, List list4, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this(list, list2, (i & 4) != 0 ? null : list3, (i & 8) != 0 ? null : list4);
        }
    }
}
