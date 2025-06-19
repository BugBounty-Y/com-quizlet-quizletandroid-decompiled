package com.quizlet.quizletandroid.ui.common.adapter.viewholder;

import android.app.AlertDialog;
import android.content.Intent;
import android.content.res.Resources;
import android.view.View;
import androidx.fragment.app.I;
import androidx.lifecycle.p0;
import com.comscore.streaming.EventType;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_barcode.H6;
import com.google.android.gms.internal.mlkit_vision_barcode.I6;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.model.ProfileImage;
import com.quizlet.assembly.widgets.input.AssemblyInputLayout;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.features.match.settings.MatchSettingsData;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.dialogs.BaseConvertableModalDialogFragment;
import com.quizlet.quizletandroid.ui.common.dialogs.TextOverlayDialogFragment;
import com.quizlet.quizletandroid.ui.diagramming.DiagramView;
import com.quizlet.quizletandroid.ui.group.GroupFragment;
import com.quizlet.quizletandroid.ui.group.classcontent.ClassContentListFragment;
import com.quizlet.quizletandroid.ui.joincontenttofolder.SelectableFolderListFragment;
import com.quizlet.quizletandroid.ui.live.QuizletLiveActivity;
import com.quizlet.quizletandroid.ui.login.OldNativeSignupFragment;
import com.quizlet.quizletandroid.ui.login.ParentEmailFragment;
import com.quizlet.quizletandroid.ui.login.UserBirthdayFragment;
import com.quizlet.quizletandroid.ui.login.n;
import com.quizlet.quizletandroid.ui.qrcodes.QLiveQrCodeReaderActivity;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.w;
import com.quizlet.quizletandroid.ui.studymodes.match.settings.MatchSettingsActivity;
import com.quizlet.quizletandroid.ui.studymodes.match.settings.MatchSettingsFragment;
import com.quizlet.quizletandroid.ui.studymodes.testmode.activities.TestStudyModeActivity;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeActivity;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeCheckPointView;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteSettingsActivity;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteStudyModeConfig;
import com.quizlet.quizletandroid.ui.usersettings.fragments.ChangeProfileImageFragment;
import com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment;
import com.quizlet.uicommon.ui.common.dialogs.ImageOverlayDialogFragment;
import com.quizlet.uicommon.ui.common.dialogs.e;
import com.quizlet.uicommon.ui.common.overflowmenu.FullscreenOverflowFragment;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import io.reactivex.rxjava3.core.o;
import java.util.ArrayList;
import java.util.Objects;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final /* synthetic */ class h implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ h(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) throws Exception {
        int i = 2;
        char c = 1;
        char c2 = 1;
        char c3 = 1;
        boolean z = false;
        z = false;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                ((com.quizlet.quizletandroid.ui.common.adapter.g) obj).b();
                return;
            case 1:
                ((BaseConvertableModalDialogFragment) obj).H(false, false);
                return;
            case 2:
                int i2 = TextOverlayDialogFragment.w;
                ((TextOverlayDialogFragment) obj).H(false, false);
                return;
            case 3:
                ((DiagramView) obj).c.b(Unit.a);
                return;
            case 4:
                String str = GroupFragment.M;
                GroupFragment groupFragment = (GroupFragment) obj;
                EventLogger eventLogger = groupFragment.k;
                if (eventLogger == null) {
                    Intrinsics.m("eventLogger");
                    throw null;
                }
                eventLogger.p(groupFragment.U());
                com.quizlet.infra.legacysyncengine.managers.d dVar = groupFragment.r;
                if (dVar == null) {
                    Intrinsics.m("loggedInUserManager");
                    throw null;
                }
                DBUser dBUser = dVar.r;
                Intrinsics.d(dBUser);
                DBGroupMembership dBGroupMembershipMakeGroupMembership = DBGroupMembership.makeGroupMembership(dBUser.getId(), groupFragment.U(), 1);
                IQuizletApiClient iQuizletApiClient = groupFragment.n;
                if (iQuizletApiClient == null) {
                    Intrinsics.m("quizletApiClient");
                    throw null;
                }
                long userId = dBGroupMembershipMakeGroupMembership.getUserId();
                long classId = dBGroupMembershipMakeGroupMembership.getClassId();
                int level = dBGroupMembershipMakeGroupMembership.getLevel();
                String str2 = (String) groupFragment.B.getValue();
                Intrinsics.checkNotNullExpressionValue(str2, "<get-autoJoinCode>(...)");
                io.reactivex.rxjava3.internal.operators.single.g gVarE = iQuizletApiClient.y(userId, classId, str2, level).e(com.quizlet.quizletandroid.ui.group.f.b);
                o oVar = groupFragment.q;
                if (oVar == null) {
                    Intrinsics.m("requestScheduler");
                    throw null;
                }
                io.reactivex.rxjava3.internal.operators.single.k kVarL = gVarE.l(oVar);
                o oVar2 = groupFragment.p;
                if (oVar2 == null) {
                    Intrinsics.m("mainThreadScheduler");
                    throw null;
                }
                io.reactivex.rxjava3.internal.observers.e eVarI = new io.reactivex.rxjava3.internal.operators.single.e(new io.reactivex.rxjava3.internal.operators.single.d(kVarL.h(oVar2), new com.quizlet.quizletandroid.ui.group.g(groupFragment, z ? 1 : 0), c3 == true ? 1 : 0), new com.quizlet.eventlogger.e(groupFragment, 19), c2 == true ? 1 : 0).i(new com.quizlet.quizletandroid.ui.group.g(groupFragment, c == true ? 1 : 0), new com.quizlet.quizletandroid.ui.group.g(groupFragment, i));
                Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
                groupFragment.I(eVarI);
                return;
            case 5:
                String str3 = ClassContentListFragment.n;
                com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a aVarU = ((ClassContentListFragment) obj).U();
                if (aVarU.g.p()) {
                    aVarU.m.j(new com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.i(aVarU.o));
                    return;
                } else {
                    aVarU.n.j(com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.b.a);
                    return;
                }
            case 6:
                com.quizlet.quizletandroid.ui.joincontenttofolder.k kVar = ((SelectableFolderListFragment) obj).t;
                if (kVar != null) {
                    kVar.r.l(com.quizlet.quizletandroid.ui.joincontenttofolder.c.a);
                    return;
                } else {
                    Intrinsics.m("viewModel");
                    throw null;
                }
            case 7:
                int i3 = QuizletLiveActivity.z;
                QuizletLiveActivity quizletLiveActivity = (QuizletLiveActivity) obj;
                if (quizletLiveActivity.isFinishing()) {
                    return;
                }
                quizletLiveActivity.e0().b.a.x("quizlet_live_did_tap_scan_qr_code_instead");
                timber.log.c.a.g("Opted to scan QR code instead", new Object[0]);
                GoogleApiAvailability googleApiAvailability = quizletLiveActivity.w;
                if (googleApiAvailability == null) {
                    Intrinsics.m("googleApiAvailability");
                    throw null;
                }
                int iC = googleApiAvailability.c(quizletLiveActivity, com.google.android.gms.common.c.a);
                if (iC == 0) {
                    quizletLiveActivity.setResult(1000);
                    quizletLiveActivity.finish();
                    return;
                }
                GoogleApiAvailability googleApiAvailability2 = quizletLiveActivity.w;
                if (googleApiAvailability2 == null) {
                    Intrinsics.m("googleApiAvailability");
                    throw null;
                }
                AlertDialog alertDialogD = googleApiAvailability2.d(quizletLiveActivity, iC, 9001, null);
                if (alertDialogD != null) {
                    alertDialogD.show();
                    return;
                }
                return;
            case 8:
                String str4 = OldNativeSignupFragment.x;
                ((OldNativeSignupFragment) obj).c0();
                return;
            case 9:
                String str5 = ParentEmailFragment.n;
                ParentEmailFragment parentEmailFragment = (ParentEmailFragment) obj;
                String email = String.valueOf(((com.quizlet.login.databinding.a) parentEmailFragment.J()).b.getText());
                AssemblyInputLayout parentPasswordInputLayout = ((com.quizlet.login.databinding.a) parentEmailFragment.J()).f;
                Intrinsics.checkNotNullExpressionValue(parentPasswordInputLayout, "parentPasswordInputLayout");
                String strValueOf = parentPasswordInputLayout.getVisibility() == 0 ? String.valueOf(((com.quizlet.login.databinding.a) parentEmailFragment.J()).e.getText()) : null;
                com.quizlet.quizletandroid.ui.login.viewmodels.f fVarT = parentEmailFragment.T();
                fVarT.getClass();
                Intrinsics.checkNotNullParameter(email, "email");
                if (!StringsKt.O(email)) {
                    fVarT.e.getClass();
                    if (com.quizlet.qutils.string.c.c(email)) {
                        E.A(p0.j(fVarT), null, null, new com.quizlet.quizletandroid.ui.login.viewmodels.e(fVarT, email, strValueOf, null), 3);
                        return;
                    }
                }
                fVarT.B(R.string.invalid_email_address);
                return;
            case 10:
                ((n) obj).finish();
                return;
            case 11:
                String str6 = UserBirthdayFragment.w;
                UserBirthdayFragment userBirthdayFragment = (UserBirthdayFragment) obj;
                com.bumptech.glide.c.C(userBirthdayFragment.U(), false);
                for (QFormField qFormField : userBirthdayFragment.S()) {
                    qFormField.t = 0;
                    qFormField.r = false;
                    qFormField.k(false);
                    qFormField.i();
                }
                com.quizlet.quizletandroid.ui.globalnav.composable.n nVar = new com.quizlet.quizletandroid.ui.globalnav.composable.n(0, userBirthdayFragment, UserBirthdayFragment.class, "doSubmitLogin", "doSubmitLogin()V", 0, 12);
                androidx.work.impl.model.l lVar = userBirthdayFragment.h;
                if (lVar != null) {
                    userBirthdayFragment.I(B7.b(lVar.r(), io.reactivex.rxjava3.kotlin.c.b, new com.quizlet.features.setpage.header.ui.g(16, userBirthdayFragment, nVar)));
                    return;
                } else {
                    Intrinsics.m("signUpRequestParentEmailFeature");
                    throw null;
                }
            case 12:
                String str7 = QLiveQrCodeReaderActivity.t;
                s sVarC0 = ((QLiveQrCodeReaderActivity) obj).c0();
                ((com.quizlet.features.emailconfirmation.logging.a) sVarC0.d).a.x("quizlet_live_did_tap_enter_game_code_instead");
                QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity = (QLiveQrCodeReaderActivity) sVarC0.h;
                if (qLiveQrCodeReaderActivity != null) {
                    qLiveQrCodeReaderActivity.d0();
                    return;
                } else {
                    Intrinsics.m("view");
                    throw null;
                }
            case 13:
                com.quizlet.quizletandroid.ui.setcreation.activities.d dVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.d) obj;
                if (dVar2.B == null || dVar2.isFinishing()) {
                    return;
                }
                dVar2.B.V();
                return;
            case 14:
                com.quizlet.quizletandroid.ui.setcreation.activities.o oVar3 = (com.quizlet.quizletandroid.ui.setcreation.activities.o) obj;
                com.quizlet.quizletandroid.util.j jVar = ((com.quizlet.quizletandroid.ui.setcreation.activities.n) oVar3.c.get(oVar3.getAdapterPosition())).b;
                com.quizlet.quizletandroid.util.j jVar2 = com.quizlet.quizletandroid.util.j.b;
                boolean z2 = oVar3.d;
                if (jVar != jVar2 || !z2) {
                    oVar3.b.invoke(((com.quizlet.quizletandroid.ui.setcreation.activities.n) oVar3.c.get(oVar3.getAdapterPosition())).b, Boolean.valueOf(jVar == jVar2 && !z2));
                    return;
                }
                View itemView = oVar3.itemView;
                Intrinsics.checkNotNullExpressionValue(itemView, "itemView");
                Resources resources = itemView.getContext().getResources();
                com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = new com.quizlet.infra.legacysyncengine.tasks.parse.b(oVar3, 15);
                e.a aVar = new e.a(itemView.getContext());
                aVar.d = resources.getString(R.string.override_password_dialog_title);
                aVar.e = resources.getString(R.string.override_password_dialog_message);
                aVar.i = resources.getString(R.string.override_password_dialog_yes);
                aVar.j = bVar;
                aVar.k = resources.getString(R.string.override_password_dialog_no);
                aVar.l = bVar;
                aVar.g();
                return;
            case 15:
                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = ((com.quizlet.quizletandroid.ui.setcreation.viewholders.c) obj).a;
                fVar.m();
                ArrayList arrayList = fVar.p;
                if (arrayList == null) {
                    return;
                }
                fVar.d(arrayList.size());
                if (fVar.k() != null) {
                    fVar.k().e("add_term");
                    return;
                }
                return;
            case 16:
                String str8 = MatchSettingsActivity.q;
                ((MatchSettingsActivity) obj).onBackPressed();
                return;
            case 17:
                String str9 = MatchSettingsFragment.k;
                com.onetrust.otpublishers.headless.UI.TVUI.datautils.a aVarW = ((MatchSettingsFragment) obj).W();
                MatchSettingsFragment matchSettingsFragment = (MatchSettingsFragment) aVarW.c;
                if (matchSettingsFragment == null) {
                    Intrinsics.m("view");
                    throw null;
                }
                MatchSettingsData matchSettingsDataF = aVarW.f(matchSettingsFragment.T());
                MatchSettingsFragment matchSettingsFragment2 = (MatchSettingsFragment) aVarW.c;
                if (matchSettingsFragment2 == null) {
                    Intrinsics.m("view");
                    throw null;
                }
                matchSettingsFragment2.Y(matchSettingsDataF, true);
                MatchSettingsFragment matchSettingsFragment3 = (MatchSettingsFragment) aVarW.c;
                if (matchSettingsFragment3 == null) {
                    Intrinsics.m("view");
                    throw null;
                }
                I activity = matchSettingsFragment3.getActivity();
                if (activity != null) {
                    activity.finish();
                    return;
                }
                return;
            case 18:
                String str10 = TestStudyModeActivity.v;
                ((TestStudyModeActivity) obj).c0().F();
                return;
            case 19:
                WriteModeActivity writeModeActivity = (WriteModeActivity) obj;
                StudyableModel studyableModel = writeModeActivity.u.f;
                if (studyableModel == null) {
                    return;
                }
                WriteStudyModeConfig writeStudyModeConfigF = writeModeActivity.t1.f();
                int size = writeModeActivity.u.u.size();
                DBTerm dBTerm = writeModeActivity.Y;
                if (dBTerm != null && dBTerm.hasDefinitionImage()) {
                    z = true;
                }
                String wordLang = studyableModel.getWordLang();
                String defLang = studyableModel.getDefLang();
                Intent intent = new Intent(writeModeActivity, (Class<?>) WriteSettingsActivity.class);
                intent.putExtra("learnModeConfig", writeStudyModeConfigF);
                intent.putExtra("selectedTermCount", size);
                intent.putExtra("showImageOptions", z);
                intent.putExtra("studyableWordLanguageCode", wordLang);
                intent.putExtra("studyableDefinitionLanguageCode", defLang);
                writeModeActivity.startActivityForResult(intent, 1);
                return;
            case 20:
                com.quizlet.quizletandroid.ui.studymodes.write.e eVar = ((WriteModeCheckPointView) ((com.quizlet.data.repository.explanations.myexplanations.a) obj).c).j;
                if (eVar != null) {
                    WriteModeActivity writeModeActivity2 = (WriteModeActivity) eVar;
                    writeModeActivity2.U();
                    io.reactivex.rxjava3.subjects.f fVar2 = writeModeActivity2.u.g;
                    o oVarI = writeModeActivity2.s1.i();
                    fVar2.getClass();
                    Objects.requireNonNull(oVarI, "scheduler is null");
                    writeModeActivity2.w.b(new io.reactivex.rxjava3.internal.operators.completable.h(fVar2, oVarI, 0).f(new com.quizlet.eventlogger.e(writeModeActivity2, 21), new com.quizlet.billing.subscriptions.c(2)));
                    return;
                }
                return;
            case 21:
                ((WriteSettingsActivity) obj).onBackPressed();
                return;
            case EventType.WINDOW_STATE /* 22 */:
                com.quizlet.quizletandroid.ui.studymodes.write.n nVar2 = (com.quizlet.quizletandroid.ui.studymodes.write.n) obj;
                nVar2.R(true);
                nVar2.getActivity().finish();
                return;
            case EventType.AUDIO /* 23 */:
                ChangeProfileImageFragment changeProfileImageFragment = ((com.quizlet.quizletandroid.ui.usersettings.adapters.a) obj).d;
                changeProfileImageFragment.W();
                if (!changeProfileImageFragment.getContext().getPackageManager().hasSystemFeature("android.hardware.camera.any")) {
                    timber.log.c.a.e(new RuntimeException("User does not have a camera"));
                    String string = changeProfileImageFragment.getString(R.string.no_camera_detected);
                    View viewFindViewById = changeProfileImageFragment.getActivity().findViewById(R.id.coordinator_layout);
                    if (viewFindViewById != null) {
                        com.google.android.material.snackbar.h hVarE = I6.e(viewFindViewById, string);
                        hVarE.k = 0;
                        hVarE.i();
                    }
                }
                if (androidx.core.content.c.a(changeProfileImageFragment.requireContext(), "android.permission.CAMERA") == 0) {
                    changeProfileImageFragment.W().F(changeProfileImageFragment, true);
                    return;
                }
                androidx.camera.camera2.internal.compat.workaround.e eVar2 = changeProfileImageFragment.q;
                if (eVar2 != null) {
                    eVar2.p(changeProfileImageFragment);
                    return;
                } else {
                    Intrinsics.m("mPermissionsManager");
                    throw null;
                }
            case EventType.VIDEO /* 24 */:
                androidx.activity.result.b bVar2 = ((com.quizlet.quizletandroid.ui.usersettings.adapters.b) obj).d.v;
                if (bVar2 != null) {
                    H6.d(bVar2);
                    return;
                } else {
                    Intrinsics.m("mediaRequest");
                    throw null;
                }
            case EventType.SUBS /* 25 */:
                com.quizlet.quizletandroid.ui.usersettings.adapters.d dVar3 = (com.quizlet.quizletandroid.ui.usersettings.adapters.d) obj;
                com.quizlet.quizletandroid.ui.usersettings.adapters.c cVar = dVar3.d;
                int absoluteAdapterPosition = dVar3.getAbsoluteAdapterPosition();
                int i4 = cVar.d;
                cVar.d = absoluteAdapterPosition;
                ProfileImage profileImageD = cVar.d(absoluteAdapterPosition);
                ((com.quizlet.quizletandroid.ui.usersettings.viewmodels.c) cVar.c.t.getValue()).c.c(profileImageD != null ? profileImageD.getId() : null, DBUserFields.Names.PROFILE_IMAGE_ID);
                cVar.notifyItemChanged(i4);
                cVar.notifyItemChanged(cVar.d);
                cVar.f();
                return;
            case EventType.CDN /* 26 */:
                ((w) obj).invoke();
                return;
            case 27:
                FullScreenConvertibleModalDialogFragment fullScreenConvertibleModalDialogFragment = (FullScreenConvertibleModalDialogFragment) obj;
                if (fullScreenConvertibleModalDialogFragment.getChildFragmentManager().J() == 0) {
                    fullScreenConvertibleModalDialogFragment.H(false, false);
                    return;
                } else {
                    fullScreenConvertibleModalDialogFragment.getChildFragmentManager().W();
                    return;
                }
            case 28:
                String str11 = ImageOverlayDialogFragment.x;
                ((ImageOverlayDialogFragment) obj).H(false, false);
                return;
            default:
                ((FullscreenOverflowFragment) obj).G();
                return;
        }
    }
}
