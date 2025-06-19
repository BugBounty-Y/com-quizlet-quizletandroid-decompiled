package com.quizlet.features.folders.navigation;

import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.features.infra.navigation.B;
import com.quizlet.features.infra.navigation.C;
import com.quizlet.features.infra.navigation.h;
import com.quizlet.features.infra.navigation.i;
import com.quizlet.features.infra.navigation.j;
import com.quizlet.features.infra.navigation.k;
import com.quizlet.features.infra.navigation.w;
import com.quizlet.features.infra.navigation.x;
import com.quizlet.features.infra.navigation.z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements C, i, j, w, z, h, x, B, k {
    public final /* synthetic */ C a;
    public final /* synthetic */ i b;
    public final /* synthetic */ j c;
    public final /* synthetic */ w d;
    public final /* synthetic */ z e;
    public final /* synthetic */ h f;
    public final /* synthetic */ x g;
    public final /* synthetic */ B h;
    public final /* synthetic */ k i;

    public b(C userProfileNavigation, i flashcardSetNavigation, j folderNavigation, w shareSheetNavigation, z textbookNavigation, h explanationQuestionNavigation, x studyGuideNavigation, k learnModeNavigation, B uploadNavigation) {
        Intrinsics.checkNotNullParameter(userProfileNavigation, "userProfileNavigation");
        Intrinsics.checkNotNullParameter(flashcardSetNavigation, "flashcardSetNavigation");
        Intrinsics.checkNotNullParameter(folderNavigation, "folderNavigation");
        Intrinsics.checkNotNullParameter(shareSheetNavigation, "shareSheetNavigation");
        Intrinsics.checkNotNullParameter(textbookNavigation, "textbookNavigation");
        Intrinsics.checkNotNullParameter(explanationQuestionNavigation, "explanationQuestionNavigation");
        Intrinsics.checkNotNullParameter(studyGuideNavigation, "studyGuideNavigation");
        Intrinsics.checkNotNullParameter(learnModeNavigation, "learnModeNavigation");
        Intrinsics.checkNotNullParameter(uploadNavigation, "uploadNavigation");
        this.a = userProfileNavigation;
        this.b = flashcardSetNavigation;
        this.c = folderNavigation;
        this.d = shareSheetNavigation;
        this.e = textbookNavigation;
        this.f = explanationQuestionNavigation;
        this.g = studyGuideNavigation;
        this.h = uploadNavigation;
        this.i = learnModeNavigation;
    }

    @Override // com.quizlet.features.infra.navigation.z
    public final void A(String mediaExerciseId) {
        Intrinsics.checkNotNullParameter(mediaExerciseId, "mediaExerciseId");
        this.e.A(mediaExerciseId);
    }

    @Override // com.quizlet.features.infra.navigation.h
    public final void E(String questionUuId) {
        Intrinsics.checkNotNullParameter(questionUuId, "questionUuId");
        this.f.E(questionUuId);
    }

    @Override // com.quizlet.features.infra.navigation.B
    public final void G() {
        this.h.G();
    }

    @Override // com.quizlet.features.infra.navigation.k
    public final Object a(StudyableModelData.StudyFolder studyFolder, String str, long j, kotlin.coroutines.h hVar) {
        return this.i.a(studyFolder, str, -1L, hVar);
    }

    @Override // com.quizlet.features.infra.navigation.w
    public final void c(com.quizlet.features.infra.models.share.a request) {
        Intrinsics.checkNotNullParameter(request, "request");
        this.d.c(request);
    }

    @Override // com.quizlet.features.infra.navigation.z
    public final void l(String isbn) {
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        this.e.l(isbn);
    }

    @Override // com.quizlet.features.infra.navigation.x
    public final void n(String uuid) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        this.g.n(uuid);
    }

    @Override // com.quizlet.features.infra.navigation.B
    public final void o(androidx.activity.result.b launcher, AddMaterialFolderData data) {
        Intrinsics.checkNotNullParameter(launcher, "launcher");
        Intrinsics.checkNotNullParameter(data, "data");
        this.h.o(launcher, data);
    }

    @Override // com.quizlet.features.infra.navigation.B
    public final void t(androidx.activity.result.b launcher, AddMaterialFolderData data) {
        Intrinsics.checkNotNullParameter(launcher, "launcher");
        Intrinsics.checkNotNullParameter(data, "data");
        this.h.t(launcher, data);
    }

    @Override // com.quizlet.features.infra.navigation.j
    public final void v(long j) {
        this.c.v(j);
    }

    @Override // com.quizlet.features.infra.navigation.B
    public final void w() {
        this.h.w();
    }

    @Override // com.quizlet.features.infra.navigation.C
    public final void y(long j) {
        this.a.y(j);
    }

    @Override // com.quizlet.features.infra.navigation.i
    public final void z(long j) {
        this.b.z(j);
    }
}
