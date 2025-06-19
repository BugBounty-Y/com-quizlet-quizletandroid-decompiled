package com.quizlet.remote.model.folder.course;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteRecommendedStudyMaterialModel {
    public final Integer a;
    public final Integer b;
    public final String c;
    public final Integer d;
    public final SocialProof e;

    @m(generateAdapter = true)
    @Metadata
    public static final class SocialProof {
        public final String a;
        public final Integer b;
        public final String c;

        public SocialProof(String str, Integer num, String str2) {
            this.a = str;
            this.b = num;
            this.c = str2;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof SocialProof)) {
                return false;
            }
            SocialProof socialProof = (SocialProof) obj;
            return Intrinsics.b(this.a, socialProof.a) && Intrinsics.b(this.b, socialProof.b) && Intrinsics.b(this.c, socialProof.c);
        }

        public final int hashCode() {
            String str = this.a;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            Integer num = this.b;
            int iHashCode2 = (iHashCode + (num == null ? 0 : num.hashCode())) * 31;
            String str2 = this.c;
            return iHashCode2 + (str2 != null ? str2.hashCode() : 0);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("SocialProof(actionType=");
            sb.append(this.a);
            sb.append(", userCount=");
            sb.append(this.b);
            sb.append(", lastStudied=");
            return android.support.v4.media.session.a.t(sb, this.c, ")");
        }
    }

    public RemoteRecommendedStudyMaterialModel(Integer num, Integer num2, String str, Integer num3, SocialProof socialProof) {
        this.a = num;
        this.b = num2;
        this.c = str;
        this.d = num3;
        this.e = socialProof;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteRecommendedStudyMaterialModel)) {
            return false;
        }
        RemoteRecommendedStudyMaterialModel remoteRecommendedStudyMaterialModel = (RemoteRecommendedStudyMaterialModel) obj;
        return Intrinsics.b(this.a, remoteRecommendedStudyMaterialModel.a) && Intrinsics.b(this.b, remoteRecommendedStudyMaterialModel.b) && Intrinsics.b(this.c, remoteRecommendedStudyMaterialModel.c) && Intrinsics.b(this.d, remoteRecommendedStudyMaterialModel.d) && Intrinsics.b(this.e, remoteRecommendedStudyMaterialModel.e);
    }

    public final int hashCode() {
        Integer num = this.a;
        int iHashCode = (num == null ? 0 : num.hashCode()) * 31;
        Integer num2 = this.b;
        int iHashCode2 = (iHashCode + (num2 == null ? 0 : num2.hashCode())) * 31;
        String str = this.c;
        int iHashCode3 = (iHashCode2 + (str == null ? 0 : str.hashCode())) * 31;
        Integer num3 = this.d;
        int iHashCode4 = (iHashCode3 + (num3 == null ? 0 : num3.hashCode())) * 31;
        SocialProof socialProof = this.e;
        return iHashCode4 + (socialProof != null ? socialProof.hashCode() : 0);
    }

    public final String toString() {
        return "RemoteRecommendedStudyMaterialModel(id=" + this.a + ", studyMaterialType=" + this.b + ", studyMaterialId=" + this.c + ", rank=" + this.d + ", socialProof=" + this.e + ")";
    }
}
