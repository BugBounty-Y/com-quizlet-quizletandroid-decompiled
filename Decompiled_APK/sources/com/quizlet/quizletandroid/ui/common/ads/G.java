package com.quizlet.quizletandroid.ui.common.ads;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.view.ViewGroup;
import androidx.activity.result.ActivityResult;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.i7;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import com.quizlet.eventlogger.features.pushnotifications.PushNotificationLogger;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.eventlogger.model.SearchBannerEventLog;
import com.quizlet.explanations.questiondetail.data.QuestionDetailSetUpState;
import com.quizlet.explanations.questiondetail.ui.QuestionDetailActivity;
import com.quizlet.features.infra.folder.create.CreateFolderModalFragment;
import com.quizlet.features.match.data.O;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.I1;
import com.quizlet.login.LoginNavActivity;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.globalnav.GlobalNavigationActivity;
import com.quizlet.quizletandroid.ui.joincontenttofolder.JoinContentToFolderActivity;
import com.quizlet.quizletandroid.ui.joincontenttofolder.SelectableFolderListFragment;
import com.quizlet.quizletandroid.ui.library.LibraryFragment;
import com.quizlet.quizletandroid.ui.login.ForgotUsernameDialogFragment;
import com.quizlet.quizletandroid.ui.login.accountrecovery.loginduplicate.MultipleAccountsExistPromptFragment;
import com.quizlet.quizletandroid.ui.profile.UserSetListFragment;
import com.quizlet.quizletandroid.ui.shortcuts.CreateSetShortcutInterstitialActivity;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4744m;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4748q;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import com.quizlet.quizletandroid.ui.studymodes.match.activity.MatchActivity;
import com.quizlet.quizletandroid.ui.studymodes.testmode.start.TestModeStartFragment;
import com.quizlet.quizletandroid.ui.subject.SubjectCategoryActivity;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class G implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ G(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i = 2;
        int i2 = 1;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                J it2 = (J) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                androidx.lifecycle.C lifecycle = it2.getLifecycle();
                F callback = (F) obj2;
                Intrinsics.checkNotNullParameter(lifecycle, "<this>");
                Intrinsics.checkNotNullParameter(callback, "callback");
                lifecycle.a(new com.quizlet.qutils.android.d(callback));
                return Unit.a;
            case 1:
                J it3 = (J) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                androidx.lifecycle.C lifecycle2 = it3.getLifecycle();
                F callback2 = (F) obj2;
                Intrinsics.checkNotNullParameter(lifecycle2, "<this>");
                Intrinsics.checkNotNullParameter(callback2, "callback");
                lifecycle2.a(new androidx.emoji2.text.k(callback2, i));
                return Unit.a;
            case 2:
                J it4 = (J) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                androidx.lifecycle.C lifecycle3 = it4.getLifecycle();
                com.quizlet.login.magiclink.ui.e callback3 = (com.quizlet.login.magiclink.ui.e) obj2;
                Intrinsics.checkNotNullParameter(lifecycle3, "<this>");
                Intrinsics.checkNotNullParameter(callback3, "callback");
                lifecycle3.a(new com.onetrust.otpublishers.headless.UI.Helper.a(callback3, i2));
                return Unit.a;
            case 3:
                J it5 = (J) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                androidx.lifecycle.C lifecycle4 = it5.getLifecycle();
                com.quizlet.quizletandroid.ui.common.ads.prebid.b callback4 = (com.quizlet.quizletandroid.ui.common.ads.prebid.b) obj2;
                Intrinsics.checkNotNullParameter(lifecycle4, "<this>");
                Intrinsics.checkNotNullParameter(callback4, "callback");
                lifecycle4.a(new com.quizlet.qutils.android.d(callback4));
                return Unit.a;
            case 4:
                J it6 = (J) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                androidx.lifecycle.C lifecycle5 = it6.getLifecycle();
                com.quizlet.quizletandroid.ui.common.ads.prebid.a callback5 = (com.quizlet.quizletandroid.ui.common.ads.prebid.a) obj2;
                Intrinsics.checkNotNullParameter(lifecycle5, "<this>");
                Intrinsics.checkNotNullParameter(callback5, "callback");
                lifecycle5.a(new com.onetrust.otpublishers.headless.UI.Helper.a(callback5, i2));
                return Unit.a;
            case 5:
                J it7 = (J) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                androidx.lifecycle.C lifecycle6 = it7.getLifecycle();
                com.quizlet.quizletandroid.ui.common.ads.prebid.b callback6 = (com.quizlet.quizletandroid.ui.common.ads.prebid.b) obj2;
                Intrinsics.checkNotNullParameter(lifecycle6, "<this>");
                Intrinsics.checkNotNullParameter(callback6, "callback");
                lifecycle6.a(new androidx.emoji2.text.k(callback6, i));
                return Unit.a;
            case 6:
                String str = GlobalNavigationActivity.u;
                Intrinsics.checkNotNullParameter((com.quizlet.quizletandroid.ui.startpage.nav2.model.H) obj, "it");
                GlobalNavigationActivity activity = (GlobalNavigationActivity) obj2;
                if (Build.VERSION.SDK_INT >= 33) {
                    com.quizlet.data.repository.classfolder.e eVar = activity.q;
                    if (eVar == null) {
                        Intrinsics.m("pushNotificationPermissionHandler");
                        throw null;
                    }
                    AbstractC1136h0 fragmentManager = activity.getSupportFragmentManager();
                    Intrinsics.checkNotNullExpressionValue(fragmentManager, "getSupportFragmentManager(...)");
                    Intrinsics.checkNotNullParameter(activity, "activity");
                    Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
                    if (androidx.core.content.c.a(activity, "android.permission.POST_NOTIFICATIONS") == 0) {
                        ((com.quizlet.braze.e) eVar.b).b(true);
                    } else {
                        boolean zShouldShowRequestPermissionRationale = activity.shouldShowRequestPermissionRationale("android.permission.POST_NOTIFICATIONS");
                        PushNotificationLogger pushNotificationLogger = (PushNotificationLogger) eVar.c;
                        if (zShouldShowRequestPermissionRationale) {
                            pushNotificationLogger.e();
                            com.quizlet.quizletandroid.ui.startpage.nav2.pushnotification.c cVar = new com.quizlet.quizletandroid.ui.startpage.nav2.pushnotification.c();
                            String str2 = com.quizlet.quizletandroid.ui.startpage.nav2.pushnotification.c.r;
                            cVar.n = false;
                            cVar.o = true;
                            C1121a c1121aB = androidx.compose.ui.node.B.b(fragmentManager, fragmentManager);
                            c1121aB.p = true;
                            c1121aB.i(0, cVar, str2, 1);
                            if (c1121aB.g) {
                                throw new IllegalStateException("This transaction is already being added to the back stack");
                            }
                            c1121aB.h = false;
                            c1121aB.r.B(c1121aB, false);
                            com.quizlet.quizletandroid.ui.startpage.nav2.pushnotification.a listener = new com.quizlet.quizletandroid.ui.startpage.nav2.pushnotification.a(eVar, fragmentManager);
                            Intrinsics.checkNotNullParameter(listener, "listener");
                            cVar.q = listener;
                        } else {
                            pushNotificationLogger.c();
                            androidx.activity.result.b bVar = (androidx.activity.result.b) eVar.d;
                            if (bVar == null) {
                                Intrinsics.m("requestPermissionLauncher");
                                throw null;
                            }
                            bVar.a("android.permission.POST_NOTIFICATIONS");
                        }
                    }
                }
                return Unit.a;
            case 7:
                ActivityResult it8 = (ActivityResult) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                int i3 = it8.a;
                com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar = (com.quizlet.quizletandroid.ui.globalnav.navigation.a) obj2;
                if (i3 == 100) {
                    aVar.b(null);
                } else if (i3 == 300) {
                    aVar.w();
                }
                return Unit.a;
            case 8:
                com.quizlet.quizletandroid.ui.joincontenttofolder.g gVar = (com.quizlet.quizletandroid.ui.joincontenttofolder.g) obj;
                String str3 = JoinContentToFolderActivity.r;
                JoinContentToFolderActivity joinContentToFolderActivity = (JoinContentToFolderActivity) obj2;
                if (gVar instanceof com.quizlet.quizletandroid.ui.joincontenttofolder.n) {
                    com.quizlet.quizletandroid.ui.joincontenttofolder.n nVar = (com.quizlet.quizletandroid.ui.joincontenttofolder.n) gVar;
                    nVar.getClass();
                    Intent intent = new Intent();
                    intent.putExtra("setIds", CollectionsKt.x0(nVar.a));
                    intent.putExtra("oldFolderIds", CollectionsKt.x0(nVar.c));
                    intent.putExtra("newFolderIds", CollectionsKt.x0(nVar.b));
                    Unit unit = Unit.a;
                    joinContentToFolderActivity.setResult(-1, intent);
                    joinContentToFolderActivity.finish();
                } else if (gVar instanceof com.quizlet.quizletandroid.ui.joincontenttofolder.b) {
                    com.quizlet.quizletandroid.ui.joincontenttofolder.b bVar2 = (com.quizlet.quizletandroid.ui.joincontenttofolder.b) gVar;
                    bVar2.getClass();
                    Intent intent2 = new Intent();
                    intent2.putExtra(DBGroupMembershipFields.Names.CLASS_ID, bVar2.a);
                    intent2.putExtra("oldFolderIds", CollectionsKt.x0(bVar2.c));
                    intent2.putExtra("newFolderIds", CollectionsKt.x0(bVar2.b));
                    Unit unit2 = Unit.a;
                    joinContentToFolderActivity.setResult(-1, intent2);
                    joinContentToFolderActivity.finish();
                } else if (gVar instanceof com.quizlet.quizletandroid.ui.joincontenttofolder.a) {
                    joinContentToFolderActivity.onBackPressed();
                } else if (!(gVar instanceof com.quizlet.quizletandroid.ui.joincontenttofolder.e) && !Intrinsics.b(gVar, com.quizlet.quizletandroid.ui.joincontenttofolder.c.b) && !Intrinsics.b(gVar, com.quizlet.quizletandroid.ui.joincontenttofolder.c.a) && !(gVar instanceof com.quizlet.quizletandroid.ui.joincontenttofolder.d) && !(gVar instanceof com.quizlet.quizletandroid.ui.joincontenttofolder.o)) {
                    throw new NoWhenBranchMatchedException();
                }
                return Unit.a;
            case 9:
                com.quizlet.quizletandroid.ui.joincontenttofolder.g gVar2 = (com.quizlet.quizletandroid.ui.joincontenttofolder.g) obj;
                String str4 = SelectableFolderListFragment.v;
                SelectableFolderListFragment selectableFolderListFragment = (SelectableFolderListFragment) obj2;
                if (Intrinsics.b(gVar2, com.quizlet.quizletandroid.ui.joincontenttofolder.e.a) || Intrinsics.b(gVar2, com.quizlet.quizletandroid.ui.joincontenttofolder.c.b)) {
                    selectableFolderListFragment.l.c(true);
                    selectableFolderListFragment.l.b(false);
                } else if (gVar2 instanceof com.quizlet.quizletandroid.ui.joincontenttofolder.o) {
                    com.quizlet.quizletandroid.ui.joincontenttofolder.o oVar = (com.quizlet.quizletandroid.ui.joincontenttofolder.o) gVar2;
                    com.quizlet.quizletandroid.ui.joincontenttofolder.m mVar = selectableFolderListFragment.u;
                    if (mVar == null) {
                        Intrinsics.m("folderAdapter");
                        throw null;
                    }
                    mVar.f(oVar.a);
                    selectableFolderListFragment.l.c(false);
                } else if (gVar2 instanceof com.quizlet.quizletandroid.ui.joincontenttofolder.d) {
                    timber.log.a aVar2 = timber.log.c.a;
                    ((com.quizlet.quizletandroid.ui.joincontenttofolder.d) gVar2).getClass();
                    aVar2.d(AbstractC0147y.d("Encountered Error: ", selectableFolderListFragment.getString(R.string.client_error_net_exception)), new Object[0]);
                    selectableFolderListFragment.l.c(false);
                    com.google.android.material.internal.q qVar = selectableFolderListFragment.l;
                    qVar.c = true;
                    qVar.a();
                } else if (Intrinsics.b(gVar2, com.quizlet.quizletandroid.ui.joincontenttofolder.c.a)) {
                    androidx.fragment.app.I iRequireActivity = selectableFolderListFragment.requireActivity();
                    Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
                    com.quizlet.quizletandroid.ui.joincontenttofolder.k kVar = selectableFolderListFragment.t;
                    if (kVar == null) {
                        Intrinsics.m("viewModel");
                        throw null;
                    }
                    com.quizlet.quizletandroid.ui.globalnav.composable.s sVar = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, kVar, com.quizlet.quizletandroid.ui.joincontenttofolder.k.class, "onFolderCreationFinished", "onFolderCreationFinished(Z)V", 0, 3);
                    if (!iRequireActivity.isFinishing()) {
                        AbstractC1136h0 supportFragmentManager = iRequireActivity.getSupportFragmentManager();
                        Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "getSupportFragmentManager(...)");
                        supportFragmentManager.h0("createFolderRequestKey", selectableFolderListFragment, new com.google.firebase.tracing.a(26, sVar, supportFragmentManager));
                        new CreateFolderModalFragment().O(supportFragmentManager, CreateFolderModalFragment.w);
                    }
                } else if (!Intrinsics.b(gVar2, com.quizlet.quizletandroid.ui.joincontenttofolder.a.a) && !(gVar2 instanceof com.quizlet.quizletandroid.ui.joincontenttofolder.b) && !(gVar2 instanceof com.quizlet.quizletandroid.ui.joincontenttofolder.n)) {
                    throw new NoWhenBranchMatchedException();
                }
                return Unit.a;
            case 10:
                com.quizlet.explanations.myexplanations.data.o oVar2 = (com.quizlet.explanations.myexplanations.data.o) obj;
                String str5 = LibraryFragment.n;
                LibraryFragment libraryFragment = (LibraryFragment) obj2;
                if (oVar2 instanceof com.quizlet.explanations.myexplanations.data.m) {
                    libraryFragment.U();
                    Context context = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
                    String id = ((com.quizlet.explanations.myexplanations.data.m) oVar2).a;
                    Intrinsics.checkNotNullParameter(context, "context");
                    Intrinsics.checkNotNullParameter(id, "id");
                    String str6 = QuestionDetailActivity.t;
                    context.startActivity(i7.a(context, new QuestionDetailSetUpState.WithId(id)));
                } else {
                    if (!(oVar2 instanceof com.quizlet.explanations.myexplanations.data.n)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    com.quizlet.explanations.navigation.b bVarU = libraryFragment.U();
                    Context contextRequireContext = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                    ((com.quizlet.quizletandroid.ui.navigationmanagers.b) bVarU).c(contextRequireContext, ((com.quizlet.explanations.myexplanations.data.n) oVar2).a);
                }
                return Unit.a;
            case 11:
                String str7 = MultipleAccountsExistPromptFragment.l;
                ForgotUsernameDialogFragment forgotUsernameDialogFragment = new ForgotUsernameDialogFragment();
                Intrinsics.checkNotNullExpressionValue(forgotUsernameDialogFragment, "newInstance(...)");
                forgotUsernameDialogFragment.O(((MultipleAccountsExistPromptFragment) obj2).getChildFragmentManager(), "ForgotUsernameDialogFragment");
                return Unit.a;
            case 12:
                DBStudySet studySet = (DBStudySet) obj;
                UserSetListFragment userSetListFragment = (UserSetListFragment) ((com.quizlet.login.common.interactors.d) obj2).b;
                com.quizlet.offline.managers.i iVar = (com.quizlet.offline.managers.i) userSetListFragment.y;
                iVar.getClass();
                Intrinsics.checkNotNullParameter(studySet, "studySet");
                long id2 = studySet.getId();
                DBUser creator = studySet.getCreator();
                new io.reactivex.rxjava3.internal.operators.single.d(iVar.a(id2, creator != null ? creator.getIsVerified() : false), new com.quizlet.billing.subscriptions.a(userSetListFragment, 14), i2).i(new com.quizlet.infra.legacysyncengine.managers.a(i2, userSetListFragment, studySet), new com.quizlet.billing.subscriptions.c(2));
                return null;
            case 13:
                ((ViewGroup) obj2).setVisibility(8);
                return Unit.a;
            case 14:
                A1 a1 = (A1) obj2;
                ((AndroidEventLog) obj).getPayload().setMode(a1 != null ? Integer.valueOf(a1.a()) : null);
                return Unit.a;
            case 15:
                List data = (List) obj;
                Intrinsics.checkNotNullParameter(data, "data");
                io.reactivex.rxjava3.subjects.d dVar = (io.reactivex.rxjava3.subjects.d) ((com.quizlet.data.repository.explanations.textbook.a) obj2).c;
                if (dVar != null) {
                    dVar.b(data);
                }
                return Unit.a;
            case 16:
                LoggedInUserStatus loggedInStatus = (LoggedInUserStatus) obj;
                Intrinsics.checkNotNullParameter(loggedInStatus, "loggedInStatus");
                boolean zIsLoggedIn = loggedInStatus.isLoggedIn();
                CreateSetShortcutInterstitialActivity createSetShortcutInterstitialActivity = (CreateSetShortcutInterstitialActivity) ((com.quizlet.quizletandroid.k) obj2).b;
                if (zIsLoggedIn) {
                    kotlinx.coroutines.E.A(p0.h(createSetShortcutInterstitialActivity), null, null, new com.quizlet.quizletandroid.ui.shortcuts.a(createSetShortcutInterstitialActivity, null), 3);
                } else {
                    String str8 = LoginNavActivity.i;
                    createSetShortcutInterstitialActivity.startActivity(com.google.android.gms.internal.mlkit_vision_document_scanner.B.a(createSetShortcutInterstitialActivity));
                }
                return Unit.a;
            case 17:
                long jLongValue = ((Long) obj).longValue();
                com.quizlet.quizletandroid.ui.startpage.nav2.adapters.g gVar3 = (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.g) obj2;
                String modelId = String.valueOf(jLongValue);
                Y y = gVar3.e;
                y.getClass();
                Intrinsics.checkNotNullParameter(modelId, "modelId");
                y.j.d(3, modelId);
                L l = gVar3.d;
                if (l != null) {
                    l.p.h(new C4744m(jLongValue));
                    com.quizlet.quizletandroid.ui.startpage.nav2.logging.a aVar3 = l.i;
                    aVar3.getClass();
                    com.quizlet.quizletandroid.ui.startpage.nav2.logging.a.b(aVar3, "clicked_folders", "folder", String.valueOf(jLongValue), 3);
                }
                return Unit.a;
            case 18:
                String noteUuid = (String) obj;
                Intrinsics.checkNotNullParameter(noteUuid, "it");
                com.quizlet.quizletandroid.ui.startpage.nav2.adapters.g gVar4 = (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.g) obj2;
                Y y2 = gVar4.e;
                y2.getClass();
                Intrinsics.checkNotNullParameter(noteUuid, "modelId");
                y2.j.d(20, noteUuid);
                L l2 = gVar4.d;
                if (l2 != null) {
                    Intrinsics.checkNotNullParameter(noteUuid, "noteUUID");
                    l2.p.h(new C4748q(noteUuid));
                    com.quizlet.quizletandroid.ui.startpage.nav2.logging.a aVar4 = l2.i;
                    aVar4.getClass();
                    Intrinsics.checkNotNullParameter(noteUuid, "noteUuid");
                    com.quizlet.quizletandroid.ui.startpage.nav2.logging.a.b(aVar4, "clicked_note", "note", noteUuid, 20);
                }
                return Unit.a;
            case 19:
                I1 subjectCategoryType = (I1) obj;
                Intrinsics.checkNotNullParameter(subjectCategoryType, "it");
                L l3 = ((com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.d) obj2).e;
                if (l3 != null) {
                    Intrinsics.checkNotNullParameter(subjectCategoryType, "subjectCategoryType");
                    kotlinx.coroutines.E.A(p0.j(l3), null, null, new com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.J(l3, subjectCategoryType, null), 3);
                }
                return Unit.a;
            case 20:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                ((com.quizlet.features.questionnaire.screens.c) obj2).invoke();
                return Unit.a;
            case 21:
                String str9 = MatchActivity.s;
                Intrinsics.checkNotNullParameter((it.sephiroth.android.library.xtooltip.i) obj, "it");
                ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l) obj2).invoke();
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                O matchShareData = (O) obj;
                Intrinsics.checkNotNullParameter(matchShareData, "matchShareData");
                com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g gVar5 = (com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g) obj2;
                gVar5.s.j(matchShareData);
                gVar5.j.c.I("match_high_score_share");
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.i startData = (com.quizlet.quizletandroid.ui.studymodes.testmode.start.i) obj;
                String str10 = TestModeStartFragment.l;
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.A aU = ((TestModeStartFragment) obj2).U();
                Intrinsics.d(startData);
                aU.getClass();
                Intrinsics.checkNotNullParameter(startData, "startData");
                aU.j = startData.c;
                kotlinx.coroutines.E.A(p0.j(aU), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.start.y(aU, startData, null), 3);
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                Long l4 = (Long) obj;
                l4.getClass();
                return Boolean.valueOf(((ArrayList) obj2).contains(l4));
            case EventType.SUBS /* 25 */:
                Long l5 = (Long) obj;
                l5.getClass();
                return (DBTerm) ((LinkedHashMap) obj2).get(l5);
            case EventType.CDN /* 26 */:
                com.quizlet.quizletandroid.ui.subject.viewmodel.d dVar2 = (com.quizlet.quizletandroid.ui.subject.viewmodel.d) obj;
                String str11 = SubjectCategoryActivity.k;
                SubjectCategoryActivity subjectCategoryActivity = (SubjectCategoryActivity) obj2;
                if (dVar2 instanceof com.quizlet.quizletandroid.ui.subject.viewmodel.a) {
                    subjectCategoryActivity.setResult(100);
                    subjectCategoryActivity.finish();
                } else if (dVar2 instanceof com.quizlet.quizletandroid.ui.subject.viewmodel.c) {
                    subjectCategoryActivity.setResult(300);
                    subjectCategoryActivity.finish();
                } else {
                    if (!(dVar2 instanceof com.quizlet.quizletandroid.ui.subject.viewmodel.b)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    long j = ((com.quizlet.quizletandroid.ui.subject.viewmodel.b) dVar2).a;
                    subjectCategoryActivity.getClass();
                    subjectCategoryActivity.startActivity(SetPageActivity.h1.a(subjectCategoryActivity, j, false));
                }
                return Unit.a;
            case 27:
                SearchBannerEventLog.Payload createEvent = (SearchBannerEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                com.quizlet.data.model.search.c cVar2 = (com.quizlet.data.model.search.c) obj2;
                createEvent.setBannerType(cVar2.c.a());
                createEvent.setBannerName(cVar2.b);
                createEvent.setBannerUrl(cVar2.d);
                return Unit.a;
            case 28:
                AndroidEventLog logAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent, "$this$logAndroidEvent");
                com.quizlet.quizletandroid.ui.setcreation.tracking.a aVar5 = (com.quizlet.quizletandroid.ui.setcreation.tracking.a) obj2;
                if (aVar5 instanceof com.quizlet.security.challenge.eventlogging.c) {
                    logAndroidEvent.getPayload().setUrlPath(((com.quizlet.security.challenge.eventlogging.c) aVar5).b);
                }
                return Unit.a;
            default:
                Intrinsics.checkNotNullParameter((Context) obj, "<unused var>");
                return (com.google.android.gms.ads.k) obj2;
        }
    }
}
