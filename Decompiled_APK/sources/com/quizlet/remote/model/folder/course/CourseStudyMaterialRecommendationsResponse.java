package com.quizlet.remote.model.folder.course;

import com.quizlet.remote.model.base.ApiResponse;
import com.quizlet.remote.model.explanations.exercise.RemoteExerciseDetails;
import com.quizlet.remote.model.explanations.question.RemoteQuestion;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.notes.RemoteStudyNote;
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
public final class CourseStudyMaterialRecommendationsResponse extends ApiResponse {
    public final Models d;

    @m(generateAdapter = true)
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

        public Models(@InterfaceC4853h(name = "recommendedStudyMaterial") List<RemoteRecommendedStudyMaterialModel> list, @InterfaceC4853h(name = "folder") List<RemoteFolder> list2, @InterfaceC4853h(name = "user") List<RemoteUser> list3, @InterfaceC4853h(name = "set") List<RemoteSet> list4, @InterfaceC4853h(name = "textbook") List<RemoteTextbook> list5, @InterfaceC4853h(name = "textbookExercise") List<RemoteExerciseDetails> list6, @InterfaceC4853h(name = "question") List<RemoteQuestion> list7, @InterfaceC4853h(name = "studyNote") List<RemoteStudyNote> list8) {
            this.a = list;
            this.b = list2;
            this.c = list3;
            this.d = list4;
            this.e = list5;
            this.f = list6;
            this.g = list7;
            this.h = list8;
        }

        @NotNull
        public final Models copy(@InterfaceC4853h(name = "recommendedStudyMaterial") List<RemoteRecommendedStudyMaterialModel> list, @InterfaceC4853h(name = "folder") List<RemoteFolder> list2, @InterfaceC4853h(name = "user") List<RemoteUser> list3, @InterfaceC4853h(name = "set") List<RemoteSet> list4, @InterfaceC4853h(name = "textbook") List<RemoteTextbook> list5, @InterfaceC4853h(name = "textbookExercise") List<RemoteExerciseDetails> list6, @InterfaceC4853h(name = "question") List<RemoteQuestion> list7, @InterfaceC4853h(name = "studyNote") List<RemoteStudyNote> list8) {
            return new Models(list, list2, list3, list4, list5, list6, list7, list8);
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
            StringBuilder sb = new StringBuilder("Models(recommendedStudyMaterials=");
            sb.append(this.a);
            sb.append(", folders=");
            sb.append(this.b);
            sb.append(", user=");
            sb.append(this.c);
            sb.append(", studySets=");
            sb.append(this.d);
            sb.append(", textbooks=");
            sb.append(this.e);
            sb.append(", textbookExercises=");
            sb.append(this.f);
            sb.append(", explanationQuestions=");
            sb.append(this.g);
            sb.append(", studyNotes=");
            return android.support.v4.media.session.a.n(")", sb, this.h);
        }
    }

    public CourseStudyMaterialRecommendationsResponse(@InterfaceC4853h(name = "models") Models models) {
        this.d = models;
    }

    @NotNull
    public final CourseStudyMaterialRecommendationsResponse copy(@InterfaceC4853h(name = "models") Models models) {
        return new CourseStudyMaterialRecommendationsResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof CourseStudyMaterialRecommendationsResponse) && Intrinsics.b(this.d, ((CourseStudyMaterialRecommendationsResponse) obj).d);
    }

    public final int hashCode() {
        Models models = this.d;
        if (models == null) {
            return 0;
        }
        return models.hashCode();
    }

    public final String toString() {
        return "CourseStudyMaterialRecommendationsResponse(models=" + this.d + ")";
    }
}
