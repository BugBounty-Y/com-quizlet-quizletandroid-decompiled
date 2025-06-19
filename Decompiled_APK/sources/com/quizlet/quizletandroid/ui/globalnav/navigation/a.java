package com.quizlet.quizletandroid.ui.globalnav.navigation;

import android.content.Intent;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.I;
import com.quizlet.data.model.EnumC4167t0;
import com.quizlet.data.model.U0;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.infra.navigation.A;
import com.quizlet.features.infra.navigation.B;
import com.quizlet.features.infra.navigation.C;
import com.quizlet.features.infra.navigation.D;
import com.quizlet.features.infra.navigation.InterfaceC4341a;
import com.quizlet.features.infra.navigation.InterfaceC4344d;
import com.quizlet.features.infra.navigation.e;
import com.quizlet.features.infra.navigation.f;
import com.quizlet.features.infra.navigation.g;
import com.quizlet.features.infra.navigation.h;
import com.quizlet.features.infra.navigation.i;
import com.quizlet.features.infra.navigation.j;
import com.quizlet.features.infra.navigation.l;
import com.quizlet.features.infra.navigation.m;
import com.quizlet.features.infra.navigation.n;
import com.quizlet.features.infra.navigation.o;
import com.quizlet.features.infra.navigation.p;
import com.quizlet.features.infra.navigation.r;
import com.quizlet.features.infra.navigation.s;
import com.quizlet.features.infra.navigation.u;
import com.quizlet.features.infra.navigation.x;
import com.quizlet.features.infra.navigation.y;
import com.quizlet.features.infra.navigation.z;
import com.quizlet.features.universaluploadflow.navigation.d;
import com.quizlet.generated.enums.I1;
import com.quizlet.quizletandroid.ui.common.adapter.c;
import com.quizlet.quizletandroid.ui.startpage.nav2.navigation.b;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements InterfaceC4341a, InterfaceC4344d, e, f, b, g, h, j, l, m, n, p, s, u, x, y, z, A, B, C, D, o, com.quizlet.infra.contracts.debug.a, r, i {
    public final /* synthetic */ InterfaceC4341a a;
    public final /* synthetic */ InterfaceC4344d b;
    public final /* synthetic */ e c;
    public final /* synthetic */ f d;
    public final /* synthetic */ g e;
    public final /* synthetic */ h f;
    public final /* synthetic */ j g;
    public final /* synthetic */ l h;
    public final /* synthetic */ m i;
    public final /* synthetic */ n j;
    public final /* synthetic */ p k;
    public final /* synthetic */ s l;
    public final /* synthetic */ u m;
    public final /* synthetic */ x n;
    public final /* synthetic */ y o;
    public final /* synthetic */ z p;
    public final /* synthetic */ A q;
    public final /* synthetic */ B r;
    public final /* synthetic */ C s;
    public final /* synthetic */ D t;
    public final /* synthetic */ d u;
    public final /* synthetic */ o v;
    public final /* synthetic */ r w;
    public final /* synthetic */ i x;

    public a(InterfaceC4341a achievementsNavigation, InterfaceC4344d classCreationNavigation, e consentNavigation, f createFolderNavigation, b creationMenuModalNavigation, g edgyNavigation, h explanationQuestionNavigation, j folderNavigation, l loggedInUserProfileNavigation, m loginNavNavigation, n magicLinkNavigation, p onboardingNavNavigation, s qClassNavigation, u searchNavigation, x studyGuideNavigation, y subjectNavigation, z textbookNavigation, A upgradeNavigation, B uploadNavigation, C userProfileNavigation, D webPageNavigation, d universalUploadFlowNavigation, o onboardingELLNavigation, c freeTrialConfirmationNavigation, com.quizlet.shared.usecase.folderstudymaterials.a creatorMarketingNavigation, com.quizlet.quizletandroid.ui.debug.a devTool, r practiceTestsNavigation, i flashcardsNavigator) {
        Intrinsics.checkNotNullParameter(achievementsNavigation, "achievementsNavigation");
        Intrinsics.checkNotNullParameter(classCreationNavigation, "classCreationNavigation");
        Intrinsics.checkNotNullParameter(consentNavigation, "consentNavigation");
        Intrinsics.checkNotNullParameter(createFolderNavigation, "createFolderNavigation");
        Intrinsics.checkNotNullParameter(creationMenuModalNavigation, "creationMenuModalNavigation");
        Intrinsics.checkNotNullParameter(edgyNavigation, "edgyNavigation");
        Intrinsics.checkNotNullParameter(explanationQuestionNavigation, "explanationQuestionNavigation");
        Intrinsics.checkNotNullParameter(folderNavigation, "folderNavigation");
        Intrinsics.checkNotNullParameter(loggedInUserProfileNavigation, "loggedInUserProfileNavigation");
        Intrinsics.checkNotNullParameter(loginNavNavigation, "loginNavNavigation");
        Intrinsics.checkNotNullParameter(magicLinkNavigation, "magicLinkNavigation");
        Intrinsics.checkNotNullParameter(onboardingNavNavigation, "onboardingNavNavigation");
        Intrinsics.checkNotNullParameter(qClassNavigation, "qClassNavigation");
        Intrinsics.checkNotNullParameter(searchNavigation, "searchNavigation");
        Intrinsics.checkNotNullParameter(studyGuideNavigation, "studyGuideNavigation");
        Intrinsics.checkNotNullParameter(subjectNavigation, "subjectNavigation");
        Intrinsics.checkNotNullParameter(textbookNavigation, "textbookNavigation");
        Intrinsics.checkNotNullParameter(upgradeNavigation, "upgradeNavigation");
        Intrinsics.checkNotNullParameter(uploadNavigation, "uploadNavigation");
        Intrinsics.checkNotNullParameter(userProfileNavigation, "userProfileNavigation");
        Intrinsics.checkNotNullParameter(webPageNavigation, "webPageNavigation");
        Intrinsics.checkNotNullParameter(universalUploadFlowNavigation, "universalUploadFlowNavigation");
        Intrinsics.checkNotNullParameter(onboardingELLNavigation, "onboardingELLNavigation");
        Intrinsics.checkNotNullParameter(freeTrialConfirmationNavigation, "freeTrialConfirmationNavigation");
        Intrinsics.checkNotNullParameter(creatorMarketingNavigation, "creatorMarketingNavigation");
        Intrinsics.checkNotNullParameter(devTool, "devTool");
        Intrinsics.checkNotNullParameter(practiceTestsNavigation, "practiceTestsNavigation");
        Intrinsics.checkNotNullParameter(flashcardsNavigator, "flashcardsNavigator");
        this.a = achievementsNavigation;
        this.b = classCreationNavigation;
        this.c = consentNavigation;
        this.d = createFolderNavigation;
        this.e = edgyNavigation;
        this.f = explanationQuestionNavigation;
        this.g = folderNavigation;
        this.h = loggedInUserProfileNavigation;
        this.i = loginNavNavigation;
        this.j = magicLinkNavigation;
        this.k = onboardingNavNavigation;
        this.l = qClassNavigation;
        this.m = searchNavigation;
        this.n = studyGuideNavigation;
        this.o = subjectNavigation;
        this.p = textbookNavigation;
        this.q = upgradeNavigation;
        this.r = uploadNavigation;
        this.s = userProfileNavigation;
        this.t = webPageNavigation;
        this.u = universalUploadFlowNavigation;
        this.v = onboardingELLNavigation;
        this.w = practiceTestsNavigation;
        this.x = flashcardsNavigator;
    }

    @Override // com.quizlet.features.infra.navigation.z
    public final void A(String mediaExerciseId) {
        Intrinsics.checkNotNullParameter(mediaExerciseId, "mediaExerciseId");
        this.p.A(mediaExerciseId);
    }

    @Override // com.quizlet.features.infra.navigation.y
    public final void B(androidx.activity.result.b launcher, I1 subjectCategoryType) {
        Intrinsics.checkNotNullParameter(launcher, "launcher");
        Intrinsics.checkNotNullParameter(subjectCategoryType, "subjectCategoryType");
        this.o.B(launcher, subjectCategoryType);
    }

    @Override // com.quizlet.features.infra.navigation.n
    public final void C(AbstractC1136h0 fragmentManager, EnumC4167t0 logoutWarning) {
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        Intrinsics.checkNotNullParameter(logoutWarning, "logoutWarning");
        this.j.C(fragmentManager, logoutWarning);
    }

    @Override // com.quizlet.features.infra.navigation.D
    public final void D(com.quizlet.ui.models.webpage.m webPage) {
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        this.t.D(webPage);
    }

    @Override // com.quizlet.features.infra.navigation.h
    public final void E(String questionUuId) {
        Intrinsics.checkNotNullParameter(questionUuId, "questionUuId");
        this.f.E(questionUuId);
    }

    @Override // com.quizlet.features.infra.navigation.s
    public final void F(long j) {
        this.l.F(j);
    }

    @Override // com.quizlet.features.infra.navigation.B
    public final void G() {
        this.r.G();
    }

    @Override // com.quizlet.features.infra.navigation.D
    public final void H() {
        this.t.H();
    }

    @Override // com.quizlet.features.infra.navigation.o
    public final void a(AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        this.v.a(fragmentManager);
    }

    @Override // com.quizlet.features.infra.navigation.u
    public final void b(String str) {
        this.m.b(str);
    }

    @Override // com.quizlet.features.infra.navigation.p
    public final void c(androidx.activity.result.b launcher) {
        Intrinsics.checkNotNullParameter(launcher, "launcher");
        this.k.c(launcher);
    }

    @Override // com.quizlet.features.infra.navigation.e
    public final void d(I activity, com.quizlet.learn.ads.g gVar, com.quizlet.quizletandroid.ui.globalnav.composable.n nVar) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        this.c.d(activity, gVar, nVar);
    }

    @Override // com.quizlet.features.infra.navigation.InterfaceC4341a
    public final void e() {
        this.a.e();
    }

    @Override // com.quizlet.features.infra.navigation.g
    public final void f(AbstractC1136h0 fragmentManager, boolean z) {
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        this.e.f(fragmentManager, z);
    }

    @Override // com.quizlet.features.infra.navigation.r
    public final void g(String questionBankUuid) {
        U0 origin = U0.e;
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        Intrinsics.checkNotNullParameter(origin, "origin");
        this.w.g(questionBankUuid);
    }

    @Override // com.quizlet.features.infra.navigation.n
    public final void h(AbstractC1136h0 fragmentManager, String magicLinkCode) {
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        Intrinsics.checkNotNullParameter(magicLinkCode, "magicLinkCode");
        this.j.h(fragmentManager, magicLinkCode);
    }

    @Override // com.quizlet.features.infra.navigation.A
    public final void i(String upgradeSource, com.quizlet.features.infra.models.upgrade.a navigationSource, androidx.activity.result.b bVar) {
        Intrinsics.checkNotNullParameter(upgradeSource, "upgradeSource");
        Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
        this.q.i(upgradeSource, navigationSource, bVar);
    }

    @Override // com.quizlet.features.infra.navigation.m
    public final void j(Intent intent) {
        this.i.j(intent);
    }

    @Override // com.quizlet.features.infra.navigation.r
    public final void k(String questionBankUuid) {
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        this.w.k(questionBankUuid);
    }

    @Override // com.quizlet.features.infra.navigation.z
    public final void l(String isbn) {
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        this.p.l(isbn);
    }

    @Override // com.quizlet.features.infra.navigation.l
    public final void m() {
        this.h.m();
    }

    @Override // com.quizlet.features.infra.navigation.x
    public final void n(String uuid) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        this.n.n(uuid);
    }

    @Override // com.quizlet.features.infra.navigation.B
    public final void o(androidx.activity.result.b launcher, AddMaterialFolderData data) {
        Intrinsics.checkNotNullParameter(launcher, "launcher");
        Intrinsics.checkNotNullParameter(data, "data");
        this.r.o(launcher, data);
    }

    @Override // com.quizlet.features.infra.navigation.D
    public final void p(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        this.t.p(url);
    }

    @Override // com.quizlet.infra.contracts.debug.a
    public final void q() {
    }

    @Override // com.quizlet.features.infra.navigation.m
    public final void r(Intent intent) {
        this.i.r(intent);
    }

    @Override // com.quizlet.features.infra.navigation.InterfaceC4344d
    public final void s() {
        this.b.s();
    }

    @Override // com.quizlet.features.infra.navigation.B
    public final void t(androidx.activity.result.b launcher, AddMaterialFolderData data) {
        Intrinsics.checkNotNullParameter(launcher, "launcher");
        Intrinsics.checkNotNullParameter(data, "data");
        this.r.t(launcher, data);
    }

    @Override // com.quizlet.features.infra.navigation.f
    public final void u(AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        this.d.u(fragmentManager);
    }

    @Override // com.quizlet.features.infra.navigation.j
    public final void v(long j) {
        this.g.v(j);
    }

    @Override // com.quizlet.features.infra.navigation.B
    public final void w() {
        this.r.w();
    }

    @Override // com.quizlet.features.infra.navigation.m
    public final void x(String code) {
        Intrinsics.checkNotNullParameter(code, "code");
        this.i.x(code);
    }

    @Override // com.quizlet.features.infra.navigation.C
    public final void y(long j) {
        this.s.y(j);
    }

    @Override // com.quizlet.features.infra.navigation.i
    public final void z(long j) {
        this.x.z(j);
    }
}
