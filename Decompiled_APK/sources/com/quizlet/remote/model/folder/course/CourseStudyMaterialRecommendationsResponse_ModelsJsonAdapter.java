package com.quizlet.remote.model.folder.course;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.explanations.exercise.RemoteExerciseDetails;
import com.quizlet.remote.model.explanations.question.RemoteQuestion;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.folder.course.CourseStudyMaterialRecommendationsResponse;
import com.quizlet.remote.model.notes.RemoteStudyNote;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.user.RemoteUser;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class CourseStudyMaterialRecommendationsResponse_ModelsJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public final l g;
    public final l h;
    public final l i;

    public CourseStudyMaterialRecommendationsResponse_ModelsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("recommendedStudyMaterial", "folder", "user", "set", "textbook", "textbookExercise", "question", "studyNote");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, RemoteRecommendedStudyMaterialModel.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "recommendedStudyMaterials");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, RemoteFolder.class), m, "folders");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, RemoteUser.class), m, "user");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(H.f(List.class, RemoteSet.class), m, "studySets");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(H.f(List.class, RemoteTextbook.class), m, "textbooks");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(H.f(List.class, RemoteExerciseDetails.class), m, "textbookExercises");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
        l lVarA7 = moshi.a(H.f(List.class, RemoteQuestion.class), m, "explanationQuestions");
        Intrinsics.checkNotNullExpressionValue(lVarA7, "adapter(...)");
        this.h = lVarA7;
        l lVarA8 = moshi.a(H.f(List.class, RemoteStudyNote.class), m, "studyNotes");
        Intrinsics.checkNotNullExpressionValue(lVarA8, "adapter(...)");
        this.i = lVarA8;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        List list2 = null;
        List list3 = null;
        List list4 = null;
        List list5 = null;
        List list6 = null;
        List list7 = null;
        List list8 = null;
        while (reader.l()) {
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    list = (List) this.b.a(reader);
                    break;
                case 1:
                    list2 = (List) this.c.a(reader);
                    break;
                case 2:
                    list3 = (List) this.d.a(reader);
                    break;
                case 3:
                    list4 = (List) this.e.a(reader);
                    break;
                case 4:
                    list5 = (List) this.f.a(reader);
                    break;
                case 5:
                    list6 = (List) this.g.a(reader);
                    break;
                case 6:
                    list7 = (List) this.h.a(reader);
                    break;
                case 7:
                    list8 = (List) this.i.a(reader);
                    break;
            }
        }
        reader.i();
        return new CourseStudyMaterialRecommendationsResponse.Models(list, list2, list3, list4, list5, list6, list7, list8);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        CourseStudyMaterialRecommendationsResponse.Models models = (CourseStudyMaterialRecommendationsResponse.Models) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (models == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("recommendedStudyMaterial");
        this.b.g(writer, models.a);
        writer.l("folder");
        this.c.g(writer, models.b);
        writer.l("user");
        this.d.g(writer, models.c);
        writer.l("set");
        this.e.g(writer, models.d);
        writer.l("textbook");
        this.f.g(writer, models.e);
        writer.l("textbookExercise");
        this.g.g(writer, models.f);
        writer.l("question");
        this.h.g(writer, models.g);
        writer.l("studyNote");
        this.i.g(writer, models.h);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(71, "GeneratedJsonAdapter(CourseStudyMaterialRecommendationsResponse.Models)", "toString(...)");
    }
}
