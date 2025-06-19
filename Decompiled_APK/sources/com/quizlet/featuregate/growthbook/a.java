package com.quizlet.featuregate.growthbook;

import android.os.CountDownTimer;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.L0;
import com.comscore.streaming.EventType;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.data.interactor.folderwithcreator.m;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.features.flashcards.data.o;
import com.quizlet.features.folders.FolderActivity;
import com.quizlet.features.infra.folder.menu.viewmodel.n;
import com.quizlet.features.notes.upload.states.h;
import com.quizlet.features.practicetest.detail.data.C4402e;
import com.quizlet.features.practicetest.detail.data.C4404g;
import com.quizlet.features.practicetest.detail.data.F;
import com.quizlet.features.practicetest.detail.viewmodel.i;
import com.quizlet.features.questionnaire.navigation.QuestionnaireNavigationActivity;
import com.quizlet.features.setpage.studypreview.g;
import com.quizlet.features.setpage.studypreview.k;
import com.quizlet.features.setpage.termlist.TermListComposeFragment;
import com.quizlet.features.setpage.terms.ui.SelectedTermsModeFragment;
import com.quizlet.features.settings.viewmodels.p;
import com.quizlet.features.userprofile.ui.UserProfileActivity;
import com.quizlet.features.userprofile.ui.UserProfileFragment;
import com.quizlet.growthbook.QGrowthBookException;
import com.quizlet.growthbook.e;
import com.quizlet.infra.legacysyncengine.features.properties.d;
import com.quizlet.learn.ui.toolbar.j;
import com.quizlet.login.intro.data.u;
import com.quizlet.login.login.data.w;
import com.quizlet.studiablemodels.StudiableRoundProgress;
import com.sdk.growthbook.GrowthBookSDK;
import com.sdk.growthbook.model.GBValue;
import com.skydoves.balloon.compose.BalloonWindow;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.f;
import kotlinx.coroutines.flow.s0;
import timber.log.c;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ a(m mVar, p pVar) {
        this.a = 16;
        this.b = mVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        s0 s0Var;
        Object value;
        int i = 3;
        boolean zIsOn = false;
        Object[] objArr = 0;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                com.quizlet.data.repository.user.a aVar = (com.quizlet.data.repository.user.a) obj;
                e eVar = (e) ((com.quizlet.infra.contracts.growthbook.a) aVar.c);
                eVar.getClass();
                String featureName = (String) aVar.b;
                Intrinsics.checkNotNullParameter(featureName, "featureName");
                if (!eVar.i) {
                    c.a.p(new QGrowthBookException("GrowthBook may be stale when evaluating feature: ".concat(featureName)));
                }
                GrowthBookSDK growthBookSDK = eVar.g;
                if (growthBookSDK == null) {
                    Intrinsics.m("growthBookSDK");
                    throw null;
                }
                if (growthBookSDK.getForcedFeatures().containsKey(featureName)) {
                    GrowthBookSDK growthBookSDK2 = eVar.g;
                    if (growthBookSDK2 == null) {
                        Intrinsics.m("growthBookSDK");
                        throw null;
                    }
                    GBValue gBValue = growthBookSDK2.getForcedFeatures().get(featureName);
                    if (gBValue != null) {
                        zIsOn = Intrinsics.b(e.b(gBValue), Boolean.TRUE);
                    }
                } else {
                    GrowthBookSDK growthBookSDK3 = eVar.g;
                    if (growthBookSDK3 == null) {
                        Intrinsics.m("growthBookSDK");
                        throw null;
                    }
                    zIsOn = growthBookSDK3.isOn(featureName);
                }
                return Boolean.valueOf(zIsOn);
            case 1:
                com.quizlet.remote.model.notes.e eVar2 = (com.quizlet.remote.model.notes.e) obj;
                return (String) ((e) ((com.quizlet.infra.contracts.growthbook.a) eVar2.b)).a((String) eVar2.d);
            case 2:
                return Boolean.valueOf(((o) obj).e);
            case 3:
                ((FolderActivity) obj).getOnBackPressedDispatcher().c();
                return Unit.a;
            case 4:
                ((Function1) ((f) obj)).invoke(com.quizlet.features.folders.changetags.data.a.a);
                return Unit.a;
            case 5:
                ((n) obj).r(com.quizlet.features.infra.folder.menu.data.c.a);
                return Unit.a;
            case 6:
                com.quizlet.features.match.viewmodel.c cVar = (com.quizlet.features.match.viewmodel.c) obj;
                return cVar.F(cVar.c);
            case 7:
                h hVar = (h) obj;
                return C0776c.z(hVar instanceof com.quizlet.features.notes.upload.states.e ? ((com.quizlet.features.notes.upload.states.e) hVar).a() : "");
            case 8:
                return C0776c.z(Boolean.valueOf(!((F) obj).m));
            case 9:
                ((i) ((com.quizlet.features.practicetest.detail.viewmodel.a) obj)).C(C4402e.a);
                return Unit.a;
            case 10:
                ((i) obj).C(C4404g.a);
                return Unit.a;
            case 11:
                ((QuestionnaireNavigationActivity) obj).finish();
                return Unit.a;
            case 12:
                ((com.quizlet.features.notes.paywall.a) obj).invoke();
                return Unit.a;
            case 13:
                ((g) obj).C(k.a);
                return Unit.a;
            case 14:
                String str = TermListComposeFragment.m;
                ((TermListComposeFragment) obj).U().B(com.quizlet.features.setpage.termlist.data.e.a);
                return Unit.a;
            case 15:
                String str2 = SelectedTermsModeFragment.l;
                return ((SelectedTermsModeFragment) obj).requireActivity().getDefaultViewModelCreationExtras();
            case 16:
                x.d((x) ((m) obj).b);
                return Unit.a;
            case 17:
                ((com.quizlet.features.universaluploadflow.flashcards.viewmodel.e) ((com.quizlet.features.universaluploadflow.flashcards.viewmodel.a) obj)).C(com.quizlet.features.universaluploadflow.flashcards.data.f.a);
                return Unit.a;
            case 18:
                ((UserProfileActivity) obj).getOnBackPressedDispatcher().c();
                return Unit.a;
            case 19:
                ((UserProfileFragment) obj).getParentFragmentManager().V();
                return Unit.a;
            case 20:
                d dVar = (d) obj;
                dVar.getClass();
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.TERM);
                Relationship<DBTerm, DBStudySet> relationship = DBTermFields.SET;
                Long l = dVar.d;
                if (l == null) {
                    throw new IllegalArgumentException("Must call initialize first.");
                }
                bVar.b(Long.valueOf(l.longValue()), relationship);
                C4885d c4885dJ = new com.jakewharton.rxbinding4.a(new com.quizlet.infra.legacysyncengine.features.properties.a(dVar, bVar.a(), objArr == true ? 1 : 0), i).l(com.quizlet.infra.legacysyncengine.features.properties.c.k).j();
                Intrinsics.checkNotNullExpressionValue(c4885dJ, "firstOrError(...)");
                return c4885dJ;
            case 21:
                return (io.reactivex.rxjava3.disposables.a) ((com.quizlet.learn.ads.c) obj).b.get();
            case EventType.WINDOW_STATE /* 22 */:
                com.quizlet.learn.ads.h hVar2 = (com.quizlet.learn.ads.h) obj;
                hVar2.a.b();
                com.quizlet.features.universaluploadflow.flashcards.d onTick = new com.quizlet.features.universaluploadflow.flashcards.d(5);
                com.quizlet.learn.ads.g onFinish = new com.quizlet.learn.ads.g(0, hVar2, com.quizlet.learn.ads.h.class, "onTimerFinished", "onTimerFinished$learn_release()V", 0, 0);
                com.google.firebase.crashlytics.internal.settings.b bVar2 = hVar2.b;
                long j = com.quizlet.learn.ads.h.h;
                Intrinsics.checkNotNullParameter(onTick, "onTick");
                Intrinsics.checkNotNullParameter(onFinish, "onFinish");
                CountDownTimer countDownTimer = (CountDownTimer) bVar2.b;
                if (countDownTimer != null) {
                    countDownTimer.cancel();
                }
                bVar2.b = new com.quizlet.ads.ui.widgets.g(j, onTick, onFinish).start();
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                com.google.firebase.crashlytics.internal.common.i iVar = (com.google.firebase.crashlytics.internal.common.i) obj;
                if (iVar != null) {
                    iVar.run();
                }
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                StudiableRoundProgress studiableRoundProgress = ((com.quizlet.learn.ui.toolbar.i) ((j) obj)).b;
                return Float.valueOf(((int) ((studiableRoundProgress.a / studiableRoundProgress.b) * 100)) / 100.0f);
            case EventType.SUBS /* 25 */:
                com.quizlet.library.viewmodels.d dVar2 = (com.quizlet.library.viewmodels.d) obj;
                return new com.quizlet.library.paging.b(dVar2.b, dVar2.c, dVar2.d);
            case EventType.CDN /* 26 */:
                BalloonWindow.DefaultImpls.showAlignTop$default((BalloonWindow) obj, 0, 0, 3, null);
                return Unit.a;
            case 27:
                ((L0) ((com.quizlet.assembly.compose.toasts.g) obj).b).setValue(Boolean.FALSE);
                return Unit.a;
            case 28:
                com.quizlet.login.intro.viewmodel.e eVar3 = (com.quizlet.login.intro.viewmodel.e) obj;
                do {
                    s0Var = eVar3.m;
                    value = s0Var.getValue();
                } while (!s0Var.k(value, u.a((u) value, null, null, false, 27)));
                return Unit.a;
            default:
                return C0776c.z(((w) obj).e);
        }
    }

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }
}
