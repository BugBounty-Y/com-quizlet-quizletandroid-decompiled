package androidx.compose.runtime.internal;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.fragment.app.AbstractC1136h0;
import androidx.transition.C;
import androidx.work.impl.model.v;
import com.facebook.z;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3179j6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.input.AssemblyInputLayout;
import com.quizlet.data.model.EnumC4167t0;
import com.quizlet.data.model.Q1;
import com.quizlet.data.model.StudySet;
import com.quizlet.data.model.User;
import com.quizlet.data.model.Z1;
import com.quizlet.features.emailconfirmation.ui.activities.MagicLinkConfirmationActivity;
import com.quizlet.features.emailconfirmation.ui.activities.n;
import com.quizlet.features.infra.models.Creator;
import com.quizlet.features.setpage.screenstates.C4421a;
import com.quizlet.features.setpage.terms.ui.SelectedTermsModeFragment;
import com.quizlet.features.setpage.viewmodel.O;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.generated.enums.G1;
import com.quizlet.infra.legacysyncengine.datasources.w;
import com.quizlet.login.oldlogin.o;
import com.quizlet.login.recovery.forgotpassword.ui.ForgotPasswordDialogFragment;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.ActivityCenterModalFragment;
import com.quizlet.quizletandroid.ui.globalnav.GlobalNavigationActivity;
import com.quizlet.quizletandroid.ui.login.ParentEmailFragment;
import com.quizlet.quizletandroid.ui.studymodes.testmode.start.TestModeStartFragment;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import com.quizlet.uicommon.ui.common.widgets.QSegmentedControl;
import com.quizlet.upgrade.paywall.ui.PaywallFragment;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import com.quizlet.upgrade.upsell.ui.UpsellModalFragment;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.C4933y;
import kotlin.collections.V;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4942a;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes.dex */
public final /* synthetic */ class c extends C4942a implements Function2 {
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.h = i3;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        com.quizlet.qutils.string.e eVar;
        String str;
        com.quizlet.features.setpage.header.data.d dVar;
        Creator creator;
        Object value;
        Object value2;
        Object objA;
        s0 s0Var;
        Object value3;
        com.quizlet.features.setpage.terms.f fVarA;
        int i;
        s0 s0Var2;
        Object value4;
        com.quizlet.features.setpage.terms.e eVar2 = com.quizlet.features.setpage.terms.e.a;
        Object cVar = com.quizlet.features.setpage.terms.b.a;
        boolean z = true;
        Object obj3 = this.a;
        switch (this.h) {
            case 0:
                ((d) obj3).a((InterfaceC0806l) obj, ((Number) obj2).intValue());
                return Unit.a;
            case 1:
                MagicLinkConfirmationActivity magicLinkConfirmationActivity = (MagicLinkConfirmationActivity) obj3;
                String str2 = MagicLinkConfirmationActivity.r;
                magicLinkConfirmationActivity.getClass();
                if (n.a[((com.quizlet.features.emailconfirmation.data.events.b) obj).ordinal()] != 1) {
                    throw new NoWhenBranchMatchedException();
                }
                com.quizlet.quizletandroid.ui.navigationmanagers.a aVar = magicLinkConfirmationActivity.p;
                if (aVar != null) {
                    aVar.a.startActivity((Intent) aVar.b.get());
                    return Unit.a;
                }
                Intrinsics.m("navigationManager");
                throw null;
            case 2:
                ((com.quizlet.features.infra.logout.composables.a) obj3).a((EnumC4167t0) obj);
                return Unit.a;
            case 3:
                Z1 z1 = (Z1) obj;
                com.quizlet.features.setpage.header.viewmodel.f fVar = (com.quizlet.features.setpage.header.viewmodel.f) obj3;
                fVar.getClass();
                User user = z1.b;
                while (true) {
                    s0 s0Var3 = fVar.g;
                    Object value5 = s0Var3.getValue();
                    com.quizlet.features.setpage.header.data.d dVar2 = (com.quizlet.features.setpage.header.data.d) value5;
                    StudySet studySet = z1.a;
                    String string = studySet.h;
                    Intrinsics.checkNotNullParameter(string, "string");
                    com.quizlet.qutils.string.e eVar3 = new com.quizlet.qutils.string.e(string);
                    int i2 = studySet.n;
                    Object[] args = {Integer.valueOf(i2)};
                    Intrinsics.checkNotNullParameter(args, "args");
                    com.quizlet.qutils.string.d dVar3 = new com.quizlet.qutils.string.d(R.plurals.terms, i2, C4933y.P(args));
                    String string2 = studySet.m;
                    if (StringsKt.O(string2)) {
                        eVar = message;
                    } else {
                        Intrinsics.checkNotNullParameter(string2, "string");
                        eVar = new com.quizlet.qutils.string.e(string2);
                    }
                    Object[] args2 = {studySet.h, Integer.valueOf(i2)};
                    Intrinsics.checkNotNullParameter(args2, "args");
                    com.quizlet.qutils.string.d dVar4 = new com.quizlet.qutils.string.d(R.plurals.study_set_description_no_creator, i2, C4933y.P(args2));
                    if (user != null) {
                        Intrinsics.checkNotNullParameter(user, "<this>");
                        str = message;
                        dVar = dVar2;
                        creator = new Creator(AbstractC3179j6.b(user), user.a, user.b, user.i, user.e, user.l);
                    } else {
                        str = message;
                        dVar = dVar2;
                        creator = str;
                    }
                    if (s0Var3.k(value5, com.quizlet.features.setpage.header.data.d.a(dVar, eVar3, dVar3, eVar, dVar4, creator, null, 32))) {
                        return Unit.a;
                    }
                    message = str;
                }
            case 4:
                Q1 q1 = (Q1) obj;
                s0 s0Var4 = ((com.quizlet.features.setpage.header.viewmodel.f) obj3).g;
                do {
                    value = s0Var4.getValue();
                } while (!s0Var4.k(value, com.quizlet.features.setpage.header.data.d.a((com.quizlet.features.setpage.header.data.d) value, null, null, null, null, null, q1, 31)));
                return Unit.a;
            case 5:
                com.quizlet.features.setpage.terms.d dVar5 = (com.quizlet.features.setpage.terms.d) obj;
                SelectedTermsModeFragment selectedTermsModeFragment = (SelectedTermsModeFragment) obj3;
                String str3 = SelectedTermsModeFragment.l;
                QSegmentedControl qSegmentedControl = ((com.quizlet.features.setpage.databinding.b) selectedTermsModeFragment.J()).b;
                C.a(qSegmentedControl, null);
                if (Intrinsics.b(dVar5, cVar)) {
                    qSegmentedControl.setVisibility(8);
                } else {
                    if (!(dVar5 instanceof com.quizlet.features.setpage.terms.c)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    qSegmentedControl.setVisibility(0);
                    com.quizlet.features.setpage.terms.c cVar2 = (com.quizlet.features.setpage.terms.c) dVar5;
                    com.quizlet.qutils.string.d dVar6 = cVar2.c;
                    Context contextRequireContext = selectedTermsModeFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                    dVar6.getClass();
                    qSegmentedControl.setRightButtonText(AbstractC3053s1.e(dVar6, contextRequireContext));
                    Context contextRequireContext2 = selectedTermsModeFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                    com.quizlet.qutils.string.d dVar7 = cVar2.d;
                    dVar7.getClass();
                    qSegmentedControl.setRightButtonContentDescription(AbstractC3053s1.e(dVar7, contextRequireContext2));
                    qSegmentedControl.setCheckedSegment(cVar2.b ? com.quizlet.uicommon.ui.common.widgets.i.c : com.quizlet.uicommon.ui.common.widgets.i.a);
                }
                return Unit.a;
            case 6:
                DiagramData diagramData = (DiagramData) obj;
                s0 s0Var5 = ((com.quizlet.features.setpage.terms.viewmodel.c) obj3).h;
                do {
                    value2 = s0Var5.getValue();
                    objA = (com.quizlet.features.setpage.terms.g) value2;
                    if (!Intrinsics.b(objA, eVar2)) {
                        if (!(objA instanceof com.quizlet.features.setpage.terms.f)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        objA = com.quizlet.features.setpage.terms.f.a((com.quizlet.features.setpage.terms.f) objA, null, A.b(diagramData), 1);
                    }
                } while (!s0Var5.k(value2, objA));
                return Unit.a;
            case 7:
                List list = (List) obj;
                com.quizlet.features.setpage.terms.viewmodel.c cVar3 = (com.quizlet.features.setpage.terms.viewmodel.c) obj3;
                cVar3.g.n();
                do {
                    s0Var = cVar3.h;
                    value3 = s0Var.getValue();
                    com.quizlet.features.setpage.terms.g gVar = (com.quizlet.features.setpage.terms.g) value3;
                    if (Intrinsics.b(gVar, eVar2)) {
                        fVarA = new com.quizlet.features.setpage.terms.f(list, 2);
                    } else {
                        if (!(gVar instanceof com.quizlet.features.setpage.terms.f)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        fVarA = com.quizlet.features.setpage.terms.f.a((com.quizlet.features.setpage.terms.f) gVar, list, null, 2);
                    }
                } while (!s0Var.k(value3, fVarA));
                return Unit.a;
            case 8:
                com.quizlet.features.setpage.header.data.e eVar4 = (com.quizlet.features.setpage.header.data.e) obj;
                P p = (P) obj3;
                p.getClass();
                if (eVar4 instanceof com.quizlet.features.setpage.header.data.b) {
                    com.quizlet.features.setpage.header.data.b bVar = (com.quizlet.features.setpage.header.data.b) eVar4;
                    if (Intrinsics.b(bVar, com.quizlet.features.setpage.header.data.a.a)) {
                        Object[] args3 = new Object[0];
                        Intrinsics.checkNotNullParameter(args3, "args");
                        p.C(new com.quizlet.qutils.string.f(R.string.set_downloaded_successfully, C4933y.P(args3)));
                    } else if (Intrinsics.b(bVar, com.quizlet.features.setpage.header.data.a.b)) {
                        Object[] args4 = new Object[0];
                        Intrinsics.checkNotNullParameter(args4, "args");
                        p.C(new com.quizlet.qutils.string.f(R.string.could_not_handle, C4933y.P(args4)));
                    } else if (Intrinsics.b(bVar, com.quizlet.features.setpage.header.data.a.d)) {
                        Object[] args5 = new Object[0];
                        Intrinsics.checkNotNullParameter(args5, "args");
                        p.C(new com.quizlet.qutils.string.f(R.string.offline_snackbar_msg, C4933y.P(args5)));
                    } else {
                        if (!Intrinsics.b(bVar, com.quizlet.features.setpage.header.data.a.c)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        p.H(new O(p, null));
                    }
                } else {
                    if (!(eVar4 instanceof com.quizlet.features.setpage.header.data.j)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    com.quizlet.features.setpage.header.data.j jVar = (com.quizlet.features.setpage.header.data.j) eVar4;
                    if (!Intrinsics.b(jVar, com.quizlet.features.setpage.header.data.i.a)) {
                        if (!Intrinsics.b(jVar, com.quizlet.features.setpage.header.data.i.b)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        p.j1.j(C4421a.a);
                    }
                }
                return Unit.a;
            case 9:
                List list2 = (List) obj;
                com.quizlet.features.setpage.viewmodel.selectedtermsmode.b bVar2 = (com.quizlet.features.setpage.viewmodel.selectedtermsmode.b) obj3;
                bVar2.getClass();
                if (list2 == null || !list2.isEmpty()) {
                    Iterator it2 = list2.iterator();
                    i = 0;
                    while (it2.hasNext()) {
                        if (((Pair) it2.next()).b != null && (i = i + 1) < 0) {
                            B.o();
                            throw null;
                        }
                    }
                } else {
                    i = 0;
                }
                long j = bVar2.f;
                v vVar = bVar2.e;
                if (i == 0) {
                    vVar.getClass();
                    ((z) vVar.b).c(j, G1.SET, false);
                    com.quizlet.data.repository.explanations.textbook.a aVar2 = (com.quizlet.data.repository.explanations.textbook.a) vVar.c;
                    w wVarA = ((com.quizlet.infra.legacysyncengine.datasources.factory.b) aVar2.a).a(j);
                    wVarA.e((com.quizlet.infra.legacysyncengine.datasources.factory.a) aVar2.d);
                    if (wVarA.f) {
                        wVarA.f = false;
                        wVarA.c();
                    }
                } else {
                    cVar = new com.quizlet.features.setpage.terms.c(i, vVar.d(j));
                }
                do {
                    s0Var2 = bVar2.g;
                    value4 = s0Var2.getValue();
                } while (!s0Var2.k(value4, cVar));
                return Unit.a;
            case 10:
                ((com.quizlet.features.infra.logout.composables.a) obj3).a((EnumC4167t0) obj);
                return Unit.a;
            case 11:
                com.quizlet.login.recovery.forgotpassword.data.c cVar4 = (com.quizlet.login.recovery.forgotpassword.data.c) obj;
                ForgotPasswordDialogFragment forgotPasswordDialogFragment = (ForgotPasswordDialogFragment) obj3;
                String str4 = ForgotPasswordDialogFragment.C;
                forgotPasswordDialogFragment.getClass();
                if (Intrinsics.b(cVar4, com.quizlet.login.recovery.forgotpassword.data.a.a)) {
                    forgotPasswordDialogFragment.H(false, false);
                } else {
                    if (!(cVar4 instanceof com.quizlet.login.recovery.forgotpassword.data.b)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    if (forgotPasswordDialogFragment.A == null) {
                        Intrinsics.m("forgotAccountUtil");
                        throw null;
                    }
                    Context contextRequireContext3 = forgotPasswordDialogFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                    com.quizlet.login.recovery.forgotpassword.data.b bVar3 = (com.quizlet.login.recovery.forgotpassword.data.b) cVar4;
                    if (com.quizlet.login.common.util.a.a(contextRequireContext3, bVar3.a, bVar3.b, forgotPasswordDialogFragment.getString(R.string.check_email_password))) {
                        forgotPasswordDialogFragment.H(false, false);
                    }
                }
                return Unit.a;
            case 12:
                com.quizlet.features.infra.snackbar.l lVar = (com.quizlet.features.infra.snackbar.l) obj;
                ActivityCenterModalFragment activityCenterModalFragment = (ActivityCenterModalFragment) obj3;
                String str5 = ActivityCenterModalFragment.K;
                Context context = activityCenterModalFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
                lVar.getClass();
                Intrinsics.checkNotNullParameter(context, "context");
                String strA = lVar.c.a(context);
                message = strA != null ? strA : null;
                if (message != null) {
                    CoordinatorLayout view = ((com.quizlet.quizletandroid.ui.common.databinding.a) activityCenterModalFragment.P()).a;
                    Intrinsics.checkNotNullExpressionValue(view, "getRoot(...)");
                    com.quizlet.features.infra.snackbar.k kVar = lVar.a;
                    Intrinsics.checkNotNullParameter(view, "view");
                    Intrinsics.checkNotNullParameter(message, "message");
                    com.google.android.material.snackbar.h hVarA = kVar.a(view, message, new com.braze.ui.inappmessage.f(17));
                    hVarA.k = lVar.b;
                    hVarA.i();
                }
                return Unit.a;
            case 13:
                EnumC4167t0 enumC4167t0 = (EnumC4167t0) obj;
                GlobalNavigationActivity globalNavigationActivity = (GlobalNavigationActivity) obj3;
                String str6 = GlobalNavigationActivity.u;
                com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar3 = globalNavigationActivity.p;
                if (aVar3 == null) {
                    Intrinsics.m("navigationManager");
                    throw null;
                }
                AbstractC1136h0 supportFragmentManager = globalNavigationActivity.getSupportFragmentManager();
                Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "getSupportFragmentManager(...)");
                aVar3.C(supportFragmentManager, enumC4167t0);
                return Unit.a;
            case 14:
                String str7 = (String) obj;
                GlobalNavigationActivity globalNavigationActivity2 = (GlobalNavigationActivity) obj3;
                String str8 = GlobalNavigationActivity.u;
                com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar4 = globalNavigationActivity2.p;
                if (aVar4 == null) {
                    Intrinsics.m("navigationManager");
                    throw null;
                }
                aVar4.x(str7);
                globalNavigationActivity2.finish();
                return Unit.a;
            case 15:
                com.quizlet.quizletandroid.ui.login.viewmodels.h hVar = (com.quizlet.quizletandroid.ui.login.viewmodels.h) obj;
                ParentEmailFragment parentEmailFragment = (ParentEmailFragment) obj3;
                String str9 = ParentEmailFragment.n;
                AssemblyInputLayout parentEmailInputLayout = ((com.quizlet.login.databinding.a) parentEmailFragment.J()).c;
                Intrinsics.checkNotNullExpressionValue(parentEmailInputLayout, "parentEmailInputLayout");
                parentEmailFragment.V(parentEmailInputLayout, hVar.a);
                AssemblyInputLayout parentPasswordInputLayout = ((com.quizlet.login.databinding.a) parentEmailFragment.J()).f;
                Intrinsics.checkNotNullExpressionValue(parentPasswordInputLayout, "parentPasswordInputLayout");
                com.quizlet.quizletandroid.ui.login.viewmodels.d dVar8 = hVar.b;
                parentEmailFragment.V(parentPasswordInputLayout, dVar8);
                com.quizlet.login.databinding.a aVar5 = (com.quizlet.login.databinding.a) parentEmailFragment.J();
                com.quizlet.login.oldlogin.b requestType = (com.quizlet.login.oldlogin.b) parentEmailFragment.m.getValue();
                Intrinsics.checkNotNullParameter(requestType, "requestType");
                if (!(hVar.a instanceof com.quizlet.quizletandroid.ui.login.viewmodels.c) || (!(dVar8 instanceof com.quizlet.quizletandroid.ui.login.viewmodels.c) && requestType != com.quizlet.login.oldlogin.b.a)) {
                    z = false;
                }
                aVar5.g.setEnabled(z);
                return Unit.a;
            case 16:
                com.quizlet.quizletandroid.ui.login.viewmodels.g gVar2 = (com.quizlet.quizletandroid.ui.login.viewmodels.g) obj;
                ParentEmailFragment parentEmailFragment2 = (ParentEmailFragment) obj3;
                String str10 = ParentEmailFragment.n;
                Bundle bundleRequireArguments = parentEmailFragment2.requireArguments();
                Serializable serializable = bundleRequireArguments.getSerializable("pendingRequest");
                Intrinsics.e(serializable, "null cannot be cast to non-null type java.util.HashMap<kotlin.String, kotlin.String>");
                HashMap pendingRequest = (HashMap) serializable;
                boolean z2 = bundleRequireArguments.getBoolean("isSignUp");
                String authProvider = bundleRequireArguments.getString("authProvider", "");
                o oVar = (o) parentEmailFragment2.l.getValue();
                String email = gVar2.a;
                Intrinsics.d(authProvider);
                com.quizlet.login.oldlogin.b requestType2 = (com.quizlet.login.oldlogin.b) parentEmailFragment2.m.getValue();
                oVar.getClass();
                Intrinsics.checkNotNullParameter(pendingRequest, "pendingRequest");
                Intrinsics.checkNotNullParameter(email, "email");
                Intrinsics.checkNotNullParameter(authProvider, "authProvider");
                Intrinsics.checkNotNullParameter(requestType2, "requestType");
                oVar.v = z2;
                oVar.w = authProvider;
                LinkedHashMap linkedHashMapM = V.m(pendingRequest);
                linkedHashMapM.put("email", email);
                String str11 = gVar2.b;
                if (str11 != null) {
                    linkedHashMapM.put("password1", str11);
                    linkedHashMapM.put("password2", str11);
                }
                int iOrdinal = requestType2.ordinal();
                if (iOrdinal == 0) {
                    oVar.C(linkedHashMapM, z2, authProvider);
                } else {
                    if (iOrdinal != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    oVar.E(linkedHashMapM);
                }
                return Unit.a;
            case 17:
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.h hVar2 = (com.quizlet.quizletandroid.ui.studymodes.testmode.start.h) obj;
                TestModeStartFragment testModeStartFragment = (TestModeStartFragment) obj3;
                String str12 = TestModeStartFragment.l;
                testModeStartFragment.getClass();
                boolean z3 = hVar2 instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.start.f;
                com.quizlet.data.repository.folderwithcreatorinclass.e eVar5 = testModeStartFragment.k;
                if (z3) {
                    ((G) eVar5.getValue()).G(((com.quizlet.quizletandroid.ui.studymodes.testmode.start.f) hVar2).a, false);
                } else if (hVar2 instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.start.g) {
                    G.H((G) eVar5.getValue(), ((com.quizlet.quizletandroid.ui.studymodes.testmode.start.g) hVar2).a);
                } else {
                    if (!Intrinsics.b(hVar2, com.quizlet.quizletandroid.ui.studymodes.testmode.start.e.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    ((G) eVar5.getValue()).F();
                }
                return Unit.a;
            case 18:
                ((com.quizlet.uicommon.ui.common.overflowmenu.a) obj3).f((List) obj);
                return Unit.a;
            case 19:
                com.quizlet.upgrade.paywall.data.c cVar5 = (com.quizlet.upgrade.paywall.data.c) obj;
                PaywallFragment paywallFragment = (PaywallFragment) obj3;
                paywallFragment.getClass();
                if (Intrinsics.b(cVar5, com.quizlet.upgrade.paywall.data.a.a)) {
                    paywallFragment.requireActivity().finish();
                } else {
                    if (!(cVar5 instanceof com.quizlet.upgrade.paywall.data.b)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    com.quizlet.upgrade.paywall.data.b bVar4 = (com.quizlet.upgrade.paywall.data.b) cVar5;
                    String str13 = UpgradeActivity.v;
                    Context contextRequireContext4 = paywallFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext4, "requireContext(...)");
                    Intent intentI = AbstractC3242q6.i(contextRequireContext4, bVar4.a, bVar4.b);
                    androidx.activity.result.b bVar5 = paywallFragment.e;
                    if (bVar5 == null) {
                        Intrinsics.m("upgradeResultLauncher");
                        throw null;
                    }
                    bVar5.a(intentI);
                }
                return Unit.a;
            default:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                UpsellModalFragment upsellModalFragment = (UpsellModalFragment) obj3;
                upsellModalFragment.getClass();
                ((AssemblyPrimaryButton) upsellModalFragment.f0().g).setText(zBooleanValue ? R.string.upsell_try_it_button : R.string.upsell_get_quizlet_plus_button);
                return Unit.a;
        }
    }
}
