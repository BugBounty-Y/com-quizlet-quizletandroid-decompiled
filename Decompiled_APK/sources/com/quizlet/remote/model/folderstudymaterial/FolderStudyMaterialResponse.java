package com.quizlet.remote.model.folderstudymaterial;

import com.quizlet.remote.model.base.ApiResponse;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class FolderStudyMaterialResponse extends ApiResponse {
    public final Models d;

    public /* synthetic */ FolderStudyMaterialResponse(Models models, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FolderStudyMaterialResponse) && Intrinsics.b(this.d, ((FolderStudyMaterialResponse) obj).d);
    }

    public final int hashCode() {
        Models models = this.d;
        if (models == null) {
            return 0;
        }
        return models.hashCode();
    }

    public final String toString() {
        return "FolderStudyMaterialResponse(models=" + this.d + ")";
    }

    public FolderStudyMaterialResponse(Models models) {
        this.d = models;
    }

    @com.squareup.moshi.m(generateAdapter = true)
    @Metadata
    public static final class Models {
        public final List a;
        public final List b;
        public final List c;
        public final List d;
        public final List e;
        public final List f;
        public final List g;
        public final List h;

        public Models(List list, List list2, List list3, List list4, List list5, List list6, List list7, List list8) {
            this.a = list;
            this.b = list2;
            this.c = list3;
            this.d = list4;
            this.e = list5;
            this.f = list6;
            this.g = list7;
            this.h = list8;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Models)) {
                return false;
            }
            Models models = (Models) obj;
            return Intrinsics.b(this.a, models.a) && Intrinsics.b(this.b, models.b) && Intrinsics.b(this.c, models.c) && Intrinsics.b(this.d, models.d) && Intrinsics.b(this.e, models.e) && Intrinsics.b(this.f, models.f) && Intrinsics.b(this.g, models.g) && Intrinsics.b(this.h, models.h);
        }

        public final int hashCode() {
            List list = this.a;
            int iHashCode = (list == null ? 0 : list.hashCode()) * 31;
            List list2 = this.b;
            int iHashCode2 = (iHashCode + (list2 == null ? 0 : list2.hashCode())) * 31;
            List list3 = this.c;
            int iHashCode3 = (iHashCode2 + (list3 == null ? 0 : list3.hashCode())) * 31;
            List list4 = this.d;
            int iHashCode4 = (iHashCode3 + (list4 == null ? 0 : list4.hashCode())) * 31;
            List list5 = this.e;
            int iHashCode5 = (iHashCode4 + (list5 == null ? 0 : list5.hashCode())) * 31;
            List list6 = this.f;
            int iHashCode6 = (iHashCode5 + (list6 == null ? 0 : list6.hashCode())) * 31;
            List list7 = this.g;
            int iHashCode7 = (iHashCode6 + (list7 == null ? 0 : list7.hashCode())) * 31;
            List list8 = this.h;
            return iHashCode7 + (list8 != null ? list8.hashCode() : 0);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("Models(folderStudyMaterial=");
            sb.append(this.a);
            sb.append(", explanationQuestion=");
            sb.append(this.b);
            sb.append(", folder=");
            sb.append(this.c);
            sb.append(", set=");
            sb.append(this.d);
            sb.append(", studyNote=");
            sb.append(this.e);
            sb.append(", textbook=");
            sb.append(this.f);
            sb.append(", textbookExercise=");
            sb.append(this.g);
            sb.append(", user=");
            return android.support.v4.media.session.a.n(")", sb, this.h);
        }

        public /* synthetic */ Models(List list, List list2, List list3, List list4, List list5, List list6, List list7, List list8, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : list, (i & 2) != 0 ? null : list2, (i & 4) != 0 ? null : list3, (i & 8) != 0 ? null : list4, (i & 16) != 0 ? null : list5, (i & 32) != 0 ? null : list6, (i & 64) != 0 ? null : list7, (i & 128) != 0 ? null : list8);
        }
    }
}
