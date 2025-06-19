package com.quizlet.learn.data;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.studiablemodels.AssistantCheckpointProgressState;
import com.quizlet.studiablemodels.StudiableTaskProgress;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public abstract class LearnRoundSummaryData implements Parcelable {

    @Metadata
    public static final class RoundCheckpointData extends LearnRoundSummaryData {

        @NotNull
        public static final Parcelable.Creator<RoundCheckpointData> CREATOR = new v();
        public final StudyableModelData a;
        public final String b;
        public final List c;
        public final AssistantCheckpointProgressState d;
        public final StudiableTaskProgress e;
        public final int f;
        public final int g;
        public final int h;
        public final ArrayList i;
        public final boolean j;

        public RoundCheckpointData(StudyableModelData studyableModelData, String studySessionId, List roundResults, AssistantCheckpointProgressState progressState, StudiableTaskProgress studiableTaskProgress, int i, int i2, int i3, ArrayList enabledQuestionTypes, boolean z) {
            Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
            Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
            Intrinsics.checkNotNullParameter(roundResults, "roundResults");
            Intrinsics.checkNotNullParameter(progressState, "progressState");
            Intrinsics.checkNotNullParameter(enabledQuestionTypes, "enabledQuestionTypes");
            this.a = studyableModelData;
            this.b = studySessionId;
            this.c = roundResults;
            this.d = progressState;
            this.e = studiableTaskProgress;
            this.f = i;
            this.g = i2;
            this.h = i3;
            this.i = enabledQuestionTypes;
            this.j = z;
        }

        @Override // com.quizlet.learn.data.LearnRoundSummaryData
        public final StudiableTaskProgress a() {
            return this.e;
        }

        @Override // com.quizlet.learn.data.LearnRoundSummaryData
        public final AssistantCheckpointProgressState b() {
            return this.d;
        }

        @Override // com.quizlet.learn.data.LearnRoundSummaryData
        public final List c() {
            return this.c;
        }

        @Override // com.quizlet.learn.data.LearnRoundSummaryData
        public final String d() {
            return this.b;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof RoundCheckpointData)) {
                return false;
            }
            RoundCheckpointData roundCheckpointData = (RoundCheckpointData) obj;
            return Intrinsics.b(this.a, roundCheckpointData.a) && Intrinsics.b(this.b, roundCheckpointData.b) && Intrinsics.b(this.c, roundCheckpointData.c) && this.d == roundCheckpointData.d && Intrinsics.b(this.e, roundCheckpointData.e) && this.f == roundCheckpointData.f && this.g == roundCheckpointData.g && this.h == roundCheckpointData.h && Intrinsics.b(this.i, roundCheckpointData.i) && this.j == roundCheckpointData.j;
        }

        @Override // com.quizlet.learn.data.LearnRoundSummaryData
        public final StudyableModelData f() {
            return this.a;
        }

        public final int hashCode() {
            int iHashCode = (this.d.hashCode() + d0.f(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c)) * 31;
            StudiableTaskProgress studiableTaskProgress = this.e;
            return Boolean.hashCode(this.j) + d0.h(this.i, d0.b(this.h, d0.b(this.g, d0.b(this.f, (iHashCode + (studiableTaskProgress == null ? 0 : studiableTaskProgress.hashCode())) * 31, 31), 31), 31), 31);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("RoundCheckpointData(studyableModelData=");
            sb.append(this.a);
            sb.append(", studySessionId=");
            sb.append(this.b);
            sb.append(", roundResults=");
            sb.append(this.c);
            sb.append(", progressState=");
            sb.append(this.d);
            sb.append(", currentTaskProgress=");
            sb.append(this.e);
            sb.append(", numberOfTermsStudied=");
            sb.append(this.f);
            sb.append(", totalNumberTerms=");
            sb.append(this.g);
            sb.append(", totalProgress=");
            sb.append(this.h);
            sb.append(", enabledQuestionTypes=");
            sb.append(this.i);
            sb.append(", firstCheckpointInSession=");
            return android.support.v4.media.session.a.o(")", sb, this.j);
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeParcelable(this.a, i);
            dest.writeString(this.b);
            List list = this.c;
            dest.writeInt(list.size());
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                dest.writeParcelable((Parcelable) it2.next(), i);
            }
            dest.writeParcelable(this.d, i);
            dest.writeParcelable(this.e, i);
            dest.writeInt(this.f);
            dest.writeInt(this.g);
            dest.writeInt(this.h);
            ArrayList arrayList = this.i;
            dest.writeInt(arrayList.size());
            Iterator it3 = arrayList.iterator();
            while (it3.hasNext()) {
                dest.writeString(((assistantMode.enums.k) it3.next()).name());
            }
            dest.writeInt(this.j ? 1 : 0);
        }
    }

    @Metadata
    public static final class TaskCompletedCheckpointData extends LearnRoundSummaryData {

        @NotNull
        public static final Parcelable.Creator<TaskCompletedCheckpointData> CREATOR = new w();
        public final StudyableModelData a;
        public final String b;
        public final List c;
        public final AssistantCheckpointProgressState d;
        public final StudiableTaskProgress e;
        public final int f;

        public TaskCompletedCheckpointData(StudyableModelData studyableModelData, String studySessionId, List roundResults, AssistantCheckpointProgressState progressState, StudiableTaskProgress studiableTaskProgress, int i) {
            Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
            Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
            Intrinsics.checkNotNullParameter(roundResults, "roundResults");
            Intrinsics.checkNotNullParameter(progressState, "progressState");
            this.a = studyableModelData;
            this.b = studySessionId;
            this.c = roundResults;
            this.d = progressState;
            this.e = studiableTaskProgress;
            this.f = i;
        }

        @Override // com.quizlet.learn.data.LearnRoundSummaryData
        public final StudiableTaskProgress a() {
            return this.e;
        }

        @Override // com.quizlet.learn.data.LearnRoundSummaryData
        public final AssistantCheckpointProgressState b() {
            return this.d;
        }

        @Override // com.quizlet.learn.data.LearnRoundSummaryData
        public final List c() {
            return this.c;
        }

        @Override // com.quizlet.learn.data.LearnRoundSummaryData
        public final String d() {
            return this.b;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof TaskCompletedCheckpointData)) {
                return false;
            }
            TaskCompletedCheckpointData taskCompletedCheckpointData = (TaskCompletedCheckpointData) obj;
            return Intrinsics.b(this.a, taskCompletedCheckpointData.a) && Intrinsics.b(this.b, taskCompletedCheckpointData.b) && Intrinsics.b(this.c, taskCompletedCheckpointData.c) && this.d == taskCompletedCheckpointData.d && Intrinsics.b(this.e, taskCompletedCheckpointData.e) && this.f == taskCompletedCheckpointData.f;
        }

        @Override // com.quizlet.learn.data.LearnRoundSummaryData
        public final StudyableModelData f() {
            return this.a;
        }

        public final int hashCode() {
            int iHashCode = (this.d.hashCode() + d0.f(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c)) * 31;
            StudiableTaskProgress studiableTaskProgress = this.e;
            return Integer.hashCode(this.f) + ((iHashCode + (studiableTaskProgress == null ? 0 : studiableTaskProgress.hashCode())) * 31);
        }

        public final String toString() {
            return "TaskCompletedCheckpointData(studyableModelData=" + this.a + ", studySessionId=" + this.b + ", roundResults=" + this.c + ", progressState=" + this.d + ", currentTaskProgress=" + this.e + ", numFocusedLearnTerms=" + this.f + ")";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeParcelable(this.a, i);
            dest.writeString(this.b);
            List list = this.c;
            dest.writeInt(list.size());
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                dest.writeParcelable((Parcelable) it2.next(), i);
            }
            dest.writeParcelable(this.d, i);
            dest.writeParcelable(this.e, i);
            dest.writeInt(this.f);
        }
    }

    public abstract StudiableTaskProgress a();

    public abstract AssistantCheckpointProgressState b();

    public abstract List c();

    public abstract String d();

    public abstract StudyableModelData f();
}
