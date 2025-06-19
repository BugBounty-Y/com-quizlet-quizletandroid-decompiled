package com.quizlet.shared.models.api.base;

import android.support.v4.media.session.a;
import assistantMode.refactored.types.AlternativeQuestion;
import assistantMode.refactored.types.AlternativeQuestion$$serializer;
import assistantMode.refactored.types.CardSideQuestionTypeRecommendation;
import assistantMode.refactored.types.CardSideQuestionTypeRecommendation$$serializer;
import assistantMode.refactored.types.FillInTheBlankMultipleChoiceQuestionStudiableMetadata;
import assistantMode.refactored.types.FillInTheBlankMultipleChoiceQuestionStudiableMetadata$$serializer;
import assistantMode.refactored.types.FillInTheBlankQuestionStudiableMetadata;
import assistantMode.refactored.types.FillInTheBlankQuestionStudiableMetadata$$serializer;
import assistantMode.refactored.types.MLMCQDistractorStudiableMetadata;
import assistantMode.refactored.types.MLMCQDistractorStudiableMetadata$$serializer;
import assistantMode.refactored.types.MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata;
import assistantMode.refactored.types.MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata$$serializer;
import assistantMode.refactored.types.ParsedMultipleChoiceQuestionStudiableMetadata;
import assistantMode.refactored.types.ParsedMultipleChoiceQuestionStudiableMetadata$$serializer;
import com.google.android.gms.ads.g;
import com.quizlet.shared.models.api.explanations.RemoteExplanationQuestion$$serializer;
import com.quizlet.shared.models.api.explanations.RemoteTextbook$$serializer;
import com.quizlet.shared.models.api.explanations.RemoteTextbookExercise$$serializer;
import com.quizlet.shared.models.api.folders.RemoteFolder$$serializer;
import com.quizlet.shared.models.api.folderstudymaterials.RemoteFolderStudyMaterial$$serializer;
import com.quizlet.shared.models.api.notes.RemoteArtifact$$serializer;
import com.quizlet.shared.models.api.notes.RemoteMagicNote$$serializer;
import com.quizlet.shared.models.api.notes.RemoteStudyNote$$serializer;
import com.quizlet.shared.models.api.studyset.RemoteStudySet$$serializer;
import com.quizlet.shared.models.api.studyset.TermMetadata$$serializer;
import com.quizlet.shared.models.api.user.RemoteUser$$serializer;
import java.lang.annotation.Annotation;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.reflect.c;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.e;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class ModelWrapper {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] m = {new C5048d(RemoteArtifact$$serializer.INSTANCE, 0), new C5048d(RemoteExplanationQuestion$$serializer.INSTANCE, 0), new C5048d(RemoteFolder$$serializer.INSTANCE, 0), new C5048d(RemoteFolderStudyMaterial$$serializer.INSTANCE, 0), new C5048d(RemoteMagicNote$$serializer.INSTANCE, 0), new C5048d(RemoteStudySet$$serializer.INSTANCE, 0), new C5048d(new e("assistantMode.refactored.types.StudiableMetadata", K.a(assistantMode.refactored.types.f.class), new c[]{K.a(AlternativeQuestion.class), K.a(CardSideQuestionTypeRecommendation.class), K.a(FillInTheBlankMultipleChoiceQuestionStudiableMetadata.class), K.a(FillInTheBlankQuestionStudiableMetadata.class), K.a(MLMCQDistractorStudiableMetadata.class), K.a(MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata.class), K.a(ParsedMultipleChoiceQuestionStudiableMetadata.class)}, new KSerializer[]{AlternativeQuestion$$serializer.INSTANCE, CardSideQuestionTypeRecommendation$$serializer.INSTANCE, FillInTheBlankMultipleChoiceQuestionStudiableMetadata$$serializer.INSTANCE, FillInTheBlankQuestionStudiableMetadata$$serializer.INSTANCE, MLMCQDistractorStudiableMetadata$$serializer.INSTANCE, MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata$$serializer.INSTANCE, ParsedMultipleChoiceQuestionStudiableMetadata$$serializer.INSTANCE}, new Annotation[0]), 0), new C5048d(RemoteStudyNote$$serializer.INSTANCE, 0), new C5048d(TermMetadata$$serializer.INSTANCE, 0), new C5048d(RemoteTextbook$$serializer.INSTANCE, 0), new C5048d(RemoteTextbookExercise$$serializer.INSTANCE, 0), new C5048d(RemoteUser$$serializer.INSTANCE, 0)};
    public final List a;
    public final List b;
    public final List c;
    public final List d;
    public final List e;
    public final List f;
    public final List g;
    public final List h;
    public final List i;
    public final List j;
    public final List k;
    public final List l;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return ModelWrapper$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ ModelWrapper(int i, List list, List list2, List list3, List list4, List list5, List list6, List list7, List list8, List list9, List list10, List list11, List list12) {
        if ((i & 1) == 0) {
            this.a = null;
        } else {
            this.a = list;
        }
        if ((i & 2) == 0) {
            this.b = null;
        } else {
            this.b = list2;
        }
        if ((i & 4) == 0) {
            this.c = null;
        } else {
            this.c = list3;
        }
        if ((i & 8) == 0) {
            this.d = null;
        } else {
            this.d = list4;
        }
        if ((i & 16) == 0) {
            this.e = null;
        } else {
            this.e = list5;
        }
        if ((i & 32) == 0) {
            this.f = null;
        } else {
            this.f = list6;
        }
        if ((i & 64) == 0) {
            this.g = null;
        } else {
            this.g = list7;
        }
        if ((i & 128) == 0) {
            this.h = null;
        } else {
            this.h = list8;
        }
        if ((i & 256) == 0) {
            this.i = null;
        } else {
            this.i = list9;
        }
        if ((i & g.MAX_CONTENT_URL_LENGTH) == 0) {
            this.j = null;
        } else {
            this.j = list10;
        }
        if ((i & 1024) == 0) {
            this.k = null;
        } else {
            this.k = list11;
        }
        if ((i & 2048) == 0) {
            this.l = null;
        } else {
            this.l = list12;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ModelWrapper)) {
            return false;
        }
        ModelWrapper modelWrapper = (ModelWrapper) obj;
        return Intrinsics.b(this.a, modelWrapper.a) && Intrinsics.b(this.b, modelWrapper.b) && Intrinsics.b(this.c, modelWrapper.c) && Intrinsics.b(this.d, modelWrapper.d) && Intrinsics.b(this.e, modelWrapper.e) && Intrinsics.b(this.f, modelWrapper.f) && Intrinsics.b(this.g, modelWrapper.g) && Intrinsics.b(this.h, modelWrapper.h) && Intrinsics.b(this.i, modelWrapper.i) && Intrinsics.b(this.j, modelWrapper.j) && Intrinsics.b(this.k, modelWrapper.k) && Intrinsics.b(this.l, modelWrapper.l);
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
        int iHashCode8 = (iHashCode7 + (list8 == null ? 0 : list8.hashCode())) * 31;
        List list9 = this.i;
        int iHashCode9 = (iHashCode8 + (list9 == null ? 0 : list9.hashCode())) * 31;
        List list10 = this.j;
        int iHashCode10 = (iHashCode9 + (list10 == null ? 0 : list10.hashCode())) * 31;
        List list11 = this.k;
        int iHashCode11 = (iHashCode10 + (list11 == null ? 0 : list11.hashCode())) * 31;
        List list12 = this.l;
        return iHashCode11 + (list12 != null ? list12.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ModelWrapper(artifact=");
        sb.append(this.a);
        sb.append(", explanationQuestion=");
        sb.append(this.b);
        sb.append(", folder=");
        sb.append(this.c);
        sb.append(", folderStudyMaterial=");
        sb.append(this.d);
        sb.append(", magicNote=");
        sb.append(this.e);
        sb.append(", set=");
        sb.append(this.f);
        sb.append(", studiableMetadata=");
        sb.append(this.g);
        sb.append(", studyNote=");
        sb.append(this.h);
        sb.append(", term=");
        sb.append(this.i);
        sb.append(", textbook=");
        sb.append(this.j);
        sb.append(", textbookExercise=");
        sb.append(this.k);
        sb.append(", user=");
        return a.n(")", sb, this.l);
    }
}
