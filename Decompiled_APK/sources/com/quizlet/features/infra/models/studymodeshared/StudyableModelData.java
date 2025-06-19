package com.quizlet.features.infra.models.studymodeshared;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.generated.enums.G1;
import java.util.Iterator;
import java.util.Set;
import kotlin.Metadata;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface StudyableModelData extends Parcelable {

    @Metadata
    public static final class StudyFolder implements StudyableModelData {

        @NotNull
        public static final Parcelable.Creator<StudyFolder> CREATOR = new d();
        public final long a;
        public final Set b;

        public StudyFolder(long j, Set setIds) {
            Intrinsics.checkNotNullParameter(setIds, "setIds");
            this.a = j;
            this.b = setIds;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        @Override // com.quizlet.features.infra.models.studymodeshared.StudyableModelData
        public final Set e() {
            return this.b;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof StudyFolder)) {
                return false;
            }
            StudyFolder studyFolder = (StudyFolder) obj;
            return this.a == studyFolder.a && Intrinsics.b(this.b, studyFolder.b);
        }

        @Override // com.quizlet.features.infra.models.studymodeshared.StudyableModelData
        public final G1 getStudyableType() {
            return G1.FOLDER;
        }

        public final int hashCode() {
            return this.b.hashCode() + (Long.hashCode(this.a) * 31);
        }

        @Override // com.quizlet.features.infra.models.studymodeshared.StudyableModelData
        public final long k() {
            return this.a;
        }

        public final String toString() {
            return "StudyFolder(studyId=" + this.a + ", setIds=" + this.b + ")";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeLong(this.a);
            Set set = this.b;
            dest.writeInt(set.size());
            Iterator it2 = set.iterator();
            while (it2.hasNext()) {
                dest.writeLong(((Number) it2.next()).longValue());
            }
        }
    }

    @Metadata
    public static final class StudySet implements StudyableModelData {

        @NotNull
        public static final Parcelable.Creator<StudySet> CREATOR = new e();
        public final long a;

        public StudySet(long j) {
            this.a = j;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        @Override // com.quizlet.features.infra.models.studymodeshared.StudyableModelData
        public final Set e() {
            return Z.b(Long.valueOf(this.a));
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof StudySet) && this.a == ((StudySet) obj).a;
        }

        @Override // com.quizlet.features.infra.models.studymodeshared.StudyableModelData
        public final G1 getStudyableType() {
            return G1.SET;
        }

        public final int hashCode() {
            return Long.hashCode(this.a);
        }

        @Override // com.quizlet.features.infra.models.studymodeshared.StudyableModelData
        public final long k() {
            return this.a;
        }

        public final String toString() {
            return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("StudySet(studyId="));
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeLong(this.a);
        }
    }

    Set e();

    G1 getStudyableType();

    long k();
}
