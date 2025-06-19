package com.quizlet.search.composables;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import androidx.constraintlayout.widget.Group;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3134e6;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.buttons.AssemblyTextButton;
import com.quizlet.data.model.m2;
import com.quizlet.features.notes.upload.UploadNotesActivity;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import com.quizlet.shared.models.api.base.QuizletApiThreeResponse;
import com.quizlet.upgrade.data.C4833a;
import com.quizlet.upgrade.data.C4834b;
import com.quizlet.upgrade.data.C4841i;
import com.quizlet.upgrade.data.C4842j;
import com.quizlet.upgrade.data.InterfaceC4835c;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import com.quizlet.upgrade.ui.fragment.UpgradeFragment;
import com.quizlet.upgrade.ui.fragment.UpgradePlansModalFragment;
import com.quizlet.upgrade.ui.widgets.UpgradePlanChoiceCard;
import com.quizlet.upgrade.ui.widgets.UpgradeTimelineSectionLayout;
import io.ktor.client.plugins.Y;
import io.ktor.client.plugins.b0;
import java.util.concurrent.TimeUnit;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.l0;

/* loaded from: classes3.dex */
public final /* synthetic */ class E extends C4956o implements Function1 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ E(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        String strE;
        String strE2;
        String strE3;
        com.quizlet.qutils.string.f fVar;
        com.quizlet.qutils.string.f fVar2;
        com.quizlet.qutils.string.f fVar3;
        String strE4;
        boolean z = true;
        z = true;
        boolean z2 = true;
        z = true;
        eVar = null;
        eVar = null;
        View.OnClickListener eVar = null;
        switch (this.a) {
            case 0:
                String enumValue = (String) obj;
                Intrinsics.checkNotNullParameter(enumValue, "p0");
                com.quizlet.search.viewmodels.A a = (com.quizlet.search.viewmodels.A) this.receiver;
                a.getClass();
                Intrinsics.checkNotNullParameter(enumValue, "enumValue");
                a.k.a(enumValue);
                return Unit.a;
            case 1:
                return ((com.quizlet.shared.quizletapi.base.c) this.receiver).e((QuizletApiThreeResponse) obj);
            case 2:
                com.quizlet.upgrade.data.G p0 = (com.quizlet.upgrade.data.G) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                UpgradeActivity activity = (UpgradeActivity) this.receiver;
                String str = UpgradeActivity.v;
                activity.getClass();
                if (p0 instanceof com.quizlet.upgrade.data.o) {
                    activity.b0((com.quizlet.upgrade.data.o) p0);
                } else {
                    if (!(p0 instanceof InterfaceC4835c)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    InterfaceC4835c interfaceC4835c = (InterfaceC4835c) p0;
                    if (Intrinsics.b(interfaceC4835c, C4834b.a)) {
                        if (activity.q == null) {
                            Intrinsics.m("navigationManager");
                            throw null;
                        }
                        Intrinsics.checkNotNullParameter(activity, "activity");
                        int i = UploadNotesActivity.i;
                        activity.startActivity(com.google.android.gms.internal.mlkit_common.u.i(activity, m2.b, null, null, null, 28));
                        activity.finish();
                    } else {
                        if (!Intrinsics.b(interfaceC4835c, C4833a.a)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        com.quizlet.quizletandroid.ui.navigationmanagers.i iVar = activity.q;
                        if (iVar == null) {
                            Intrinsics.m("navigationManager");
                            throw null;
                        }
                        Intrinsics.checkNotNullParameter(activity, "activity");
                        if (Intrinsics.b(activity.getIntent().getAction(), "require_email_confirmation")) {
                            activity.getIntent().setAction("open_start_activity");
                        }
                        GlobalNavReroute.CreateSet createSet = GlobalNavReroute.CreateSet.a;
                        iVar.a.getClass();
                        com.quizlet.quizletandroid.util.g.a(activity, createSet);
                    }
                }
                return Unit.a;
            case 3:
                com.quizlet.upgrade.data.F p02 = (com.quizlet.upgrade.data.F) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                UpgradeFragment upgradeFragment = (UpgradeFragment) this.receiver;
                if (upgradeFragment.k == null) {
                    Intrinsics.m("navigationManager");
                    throw null;
                }
                Context context = upgradeFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
                String url = p02.a;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(url, "url");
                com.quizlet.quizletandroid.ui.webpages.a.a.b(context, url, null);
                return Unit.a;
            case 4:
                com.quizlet.upgrade.data.v item = (com.quizlet.upgrade.data.v) obj;
                Intrinsics.checkNotNullParameter(item, "p0");
                com.quizlet.upgrade.viewmodel.n nVar = (com.quizlet.upgrade.viewmodel.n) this.receiver;
                nVar.getClass();
                Intrinsics.checkNotNullParameter(item, "item");
                if (Intrinsics.b(item, com.quizlet.upgrade.data.t.b)) {
                    nVar.g.j(Unit.a);
                } else if (!Intrinsics.b(item, com.quizlet.upgrade.data.u.b) && !(item instanceof com.quizlet.upgrade.data.s)) {
                    throw new NoWhenBranchMatchedException();
                }
                return Unit.a;
            case 5:
                com.quizlet.upgrade.data.o p03 = (com.quizlet.upgrade.data.o) obj;
                Intrinsics.checkNotNullParameter(p03, "p0");
                UpgradeFragment upgradeFragment2 = (UpgradeFragment) this.receiver;
                String str2 = UpgradeFragment.r;
                upgradeFragment2.getClass();
                Bundle bundle = new Bundle(0);
                Integer num = p03.a;
                bundle.putInt("ResultUserUpgradeType", num != null ? num.intValue() : 0);
                upgradeFragment2.getParentFragmentManager().g0(bundle, "UpgradeFragmentRequestKey");
                return Unit.a;
            case 6:
                com.quizlet.upgrade.data.E e = (com.quizlet.upgrade.data.E) obj;
                UpgradeFragment upgradeFragment3 = (UpgradeFragment) this.receiver;
                String str3 = UpgradeFragment.r;
                com.onetrust.otpublishers.headless.databinding.g gVar = ((com.quizlet.upgrade.databinding.c) upgradeFragment3.J()).f;
                if (e == null) {
                    Group headerCostViews = (Group) gVar.k;
                    Intrinsics.checkNotNullExpressionValue(headerCostViews, "headerCostViews");
                    headerCostViews.setVisibility(8);
                } else {
                    QTextView qTextView = (QTextView) gVar.i;
                    Context contextRequireContext = upgradeFragment3.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                    qTextView.setText(AbstractC3053s1.e(e.b, contextRequireContext));
                }
                QTextView headerSubscriptionPeriod = (QTextView) gVar.n;
                Intrinsics.checkNotNullExpressionValue(headerSubscriptionPeriod, "headerSubscriptionPeriod");
                if (e == null || (fVar3 = e.a) == null) {
                    strE = null;
                } else {
                    Context contextRequireContext2 = upgradeFragment3.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                    strE = AbstractC3053s1.e(fVar3, contextRequireContext2);
                }
                AbstractC3134e6.i(headerSubscriptionPeriod, strE);
                QTextView headerAnnualMonthlyCost = (QTextView) gVar.j;
                Intrinsics.checkNotNullExpressionValue(headerAnnualMonthlyCost, "headerAnnualMonthlyCost");
                if (e == null || (fVar2 = e.c) == null) {
                    strE2 = null;
                } else {
                    Context contextRequireContext3 = upgradeFragment3.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                    strE2 = AbstractC3053s1.e(fVar2, contextRequireContext3);
                }
                AbstractC3134e6.i(headerAnnualMonthlyCost, strE2);
                QTextView headerCurrentSubDescription = (QTextView) gVar.l;
                Intrinsics.checkNotNullExpressionValue(headerCurrentSubDescription, "headerCurrentSubDescription");
                if (e == null || (fVar = e.d) == null) {
                    strE3 = null;
                } else {
                    Context contextRequireContext4 = upgradeFragment3.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext4, "requireContext(...)");
                    strE3 = AbstractC3053s1.e(fVar, contextRequireContext4);
                }
                AbstractC3134e6.i(headerCurrentSubDescription, strE3);
                String str4 = e != null ? e.e : null;
                QTextView headerManageSubscriptionLink = (QTextView) ((com.quizlet.upgrade.databinding.c) upgradeFragment3.J()).f.m;
                if (str4 == null) {
                    Intrinsics.checkNotNullExpressionValue(headerManageSubscriptionLink, "headerManageSubscriptionLink");
                    headerManageSubscriptionLink.setVisibility(8);
                } else {
                    Intrinsics.checkNotNullExpressionValue(headerManageSubscriptionLink, "headerManageSubscriptionLink");
                    headerManageSubscriptionLink.setVisibility(0);
                    headerManageSubscriptionLink.setOnClickListener(new com.quizlet.upgrade.ui.fragment.e(z ? 1 : 0, upgradeFragment3, str4));
                }
                com.quizlet.upgrade.data.D d = e != null ? e.f : null;
                com.onetrust.otpublishers.headless.databinding.g gVar2 = ((com.quizlet.upgrade.databinding.c) upgradeFragment3.J()).f;
                Group freeTrialViews = (Group) gVar2.h;
                if (d == null) {
                    Intrinsics.checkNotNullExpressionValue(freeTrialViews, "freeTrialViews");
                    freeTrialViews.setVisibility(8);
                } else {
                    Intrinsics.checkNotNullExpressionValue(freeTrialViews, "freeTrialViews");
                    freeTrialViews.setVisibility(0);
                    Context contextRequireContext5 = upgradeFragment3.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext5, "requireContext(...)");
                    ((QTextView) gVar2.g).setText(AbstractC3053s1.e(d.a, contextRequireContext5));
                    Context contextRequireContext6 = upgradeFragment3.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext6, "requireContext(...)");
                    ((QTextView) gVar2.q).setText(AbstractC3053s1.e(d.b, contextRequireContext6));
                    Context contextRequireContext7 = upgradeFragment3.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext7, "requireContext(...)");
                    ((QTextView) gVar2.e).setText(AbstractC3053s1.e(d.c, contextRequireContext7));
                    Context contextRequireContext8 = upgradeFragment3.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext8, "requireContext(...)");
                    ((QTextView) gVar2.f).setText(AbstractC3053s1.e(d.d, contextRequireContext8));
                }
                return Unit.a;
            case 7:
                com.quizlet.upgrade.data.B p04 = (com.quizlet.upgrade.data.B) obj;
                Intrinsics.checkNotNullParameter(p04, "p0");
                UpgradeFragment upgradeFragment4 = (UpgradeFragment) this.receiver;
                String str5 = UpgradeFragment.r;
                com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = ((com.quizlet.upgrade.databinding.c) upgradeFragment4.J()).b;
                AssemblyPrimaryButton seePlansButton = (AssemblyPrimaryButton) fVar4.e;
                Intrinsics.checkNotNullExpressionValue(seePlansButton, "seePlansButton");
                boolean z3 = p04 instanceof com.quizlet.upgrade.data.w;
                seePlansButton.setVisibility(!z3 ? 0 : 8);
                View divider = ((com.quizlet.upgrade.databinding.c) upgradeFragment4.J()).c;
                Intrinsics.checkNotNullExpressionValue(divider, "divider");
                divider.setVisibility(!z3 ? 0 : 8);
                if (!(p04 instanceof com.quizlet.upgrade.data.y) && !(p04 instanceof com.quizlet.upgrade.data.z)) {
                    z = false;
                }
                seePlansButton.setEnabled(z);
                com.quizlet.qutils.string.f fVarB = p04.b();
                Context contextRequireContext9 = upgradeFragment4.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext9, "requireContext(...)");
                fVarB.getClass();
                seePlansButton.setText(AbstractC3053s1.e(fVarB, contextRequireContext9));
                AssemblyTextButton continueFreeButton = (AssemblyTextButton) fVar4.b;
                Intrinsics.checkNotNullExpressionValue(continueFreeButton, "continueFreeButton");
                continueFreeButton.setVisibility(p04.a() ? 0 : 8);
                QTextView freeTrialText = (QTextView) fVar4.d;
                Intrinsics.checkNotNullExpressionValue(freeTrialText, "freeTrialText");
                boolean z4 = p04 instanceof com.quizlet.upgrade.data.y;
                com.quizlet.upgrade.data.y yVar = z4 ? (com.quizlet.upgrade.data.y) p04 : null;
                C4841i c4841i = yVar != null ? yVar.b : null;
                freeTrialText.setVisibility(c4841i != null ? 0 : 8);
                if (c4841i != null) {
                    Context contextRequireContext10 = upgradeFragment4.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext10, "requireContext(...)");
                    strE4 = AbstractC3053s1.e(c4841i, contextRequireContext10);
                } else {
                    strE4 = null;
                }
                freeTrialText.setText(strE4);
                Intrinsics.checkNotNullExpressionValue(seePlansButton, "seePlansButton");
                if (z4) {
                    eVar = new com.quizlet.upgrade.ui.fragment.d(upgradeFragment4, i);
                } else if (p04 instanceof com.quizlet.upgrade.data.z) {
                    eVar = new com.quizlet.upgrade.ui.fragment.e(i, upgradeFragment4, p04);
                } else if (!p04.equals(com.quizlet.upgrade.data.w.a) && !p04.equals(com.quizlet.upgrade.data.x.a) && !p04.equals(com.quizlet.upgrade.data.A.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                seePlansButton.setOnClickListener(eVar);
                return Unit.a;
            case 8:
                com.quizlet.upgrade.data.H p05 = (com.quizlet.upgrade.data.H) obj;
                Intrinsics.checkNotNullParameter(p05, "p0");
                UpgradePlansModalFragment upgradePlansModalFragment = (UpgradePlansModalFragment) this.receiver;
                String str6 = UpgradePlansModalFragment.W;
                com.quizlet.upgrade.databinding.b bVarC0 = upgradePlansModalFragment.c0();
                com.quizlet.upgrade.ui.widgets.a aVar = p05.a;
                UpgradePlanChoiceCard upgradePlanChoiceCard = bVarC0.b;
                if (aVar != null) {
                    upgradePlanChoiceCard.p(aVar);
                } else {
                    Intrinsics.d(upgradePlanChoiceCard);
                    upgradePlanChoiceCard.setVisibility(8);
                }
                UpgradePlanChoiceCard upgradePlanChoiceCard2 = upgradePlansModalFragment.c0().c;
                com.quizlet.upgrade.ui.widgets.a aVar2 = p05.b;
                if (aVar2 != null) {
                    upgradePlanChoiceCard2.p(aVar2);
                } else {
                    Intrinsics.d(upgradePlanChoiceCard2);
                    upgradePlanChoiceCard2.setVisibility(8);
                }
                return Unit.a;
            case 9:
                com.quizlet.upgrade.data.m p06 = (com.quizlet.upgrade.data.m) obj;
                Intrinsics.checkNotNullParameter(p06, "p0");
                UpgradePlansModalFragment upgradePlansModalFragment2 = (UpgradePlansModalFragment) this.receiver;
                String str7 = UpgradePlansModalFragment.W;
                com.quizlet.upgrade.databinding.b bVarC02 = upgradePlansModalFragment2.c0();
                if (!(p06 instanceof C4842j) && !(p06 instanceof com.quizlet.upgrade.data.k)) {
                    z2 = false;
                }
                bVarC02.b.setSelected(z2);
                upgradePlansModalFragment2.c0().c.setSelected(p06 instanceof com.quizlet.upgrade.data.l);
                com.quizlet.upgrade.databinding.b bVarC03 = upgradePlansModalFragment2.c0();
                com.quizlet.qutils.string.f fVarD = p06.d();
                Context contextRequireContext11 = upgradePlansModalFragment2.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext11, "requireContext(...)");
                fVarD.getClass();
                bVarC03.g.setText(AbstractC3053s1.e(fVarD, contextRequireContext11));
                UpgradeTimelineSectionLayout timelineFirstTask = upgradePlansModalFragment2.c0().f;
                Intrinsics.checkNotNullExpressionValue(timelineFirstTask, "timelineFirstTask");
                UpgradePlansModalFragment.d0(timelineFirstTask, p06.c().a);
                UpgradeTimelineSectionLayout timelineSecondTask = upgradePlansModalFragment2.c0().h;
                Intrinsics.checkNotNullExpressionValue(timelineSecondTask, "timelineSecondTask");
                UpgradePlansModalFragment.d0(timelineSecondTask, p06.c().b);
                UpgradeTimelineSectionLayout timelineThirdTask = upgradePlansModalFragment2.c0().i;
                Intrinsics.checkNotNullExpressionValue(timelineThirdTask, "timelineThirdTask");
                UpgradePlansModalFragment.d0(timelineThirdTask, p06.c().c);
                com.quizlet.upgrade.databinding.b bVarC04 = upgradePlansModalFragment2.c0();
                com.quizlet.qutils.string.f fVarA = p06.a();
                Context contextRequireContext12 = upgradePlansModalFragment2.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext12, "requireContext(...)");
                fVarA.getClass();
                bVarC04.d.setText(AbstractC3053s1.e(fVarA, contextRequireContext12));
                upgradePlansModalFragment2.c0().d.setOnClickListener(new com.quizlet.upgrade.ui.fragment.e(2, upgradePlansModalFragment2, p06));
                return Unit.a;
            case 10:
                com.quizlet.upgrade.data.F p07 = (com.quizlet.upgrade.data.F) obj;
                Intrinsics.checkNotNullParameter(p07, "p0");
                ((com.quizlet.upgrade.viewmodel.h) this.receiver).n.j(p07);
                return Unit.a;
            case 11:
                Y y = (Y) obj;
                io.ktor.client.engine.okhttp.b bVar = ((io.ktor.client.engine.okhttp.f) this.receiver).d;
                okhttp3.A a2 = bVar.b;
                if (a2 == null) {
                    a2 = (okhttp3.A) io.ktor.client.engine.okhttp.f.i.getValue();
                }
                okhttp3.z zVarB = a2.b();
                com.quizlet.data.repository.explanations.exercise.b dispatcher = new com.quizlet.data.repository.explanations.exercise.b(8);
                Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
                zVarB.a = dispatcher;
                bVar.a.invoke(zVarB);
                if (y != null) {
                    Long l = y.b;
                    if (l != null) {
                        long jLongValue = l.longValue();
                        org.slf4j.b bVar2 = b0.a;
                        if (jLongValue == Long.MAX_VALUE) {
                            jLongValue = 0;
                        }
                        TimeUnit unit = TimeUnit.MILLISECONDS;
                        Intrinsics.checkNotNullParameter(unit, "unit");
                        zVarB.v = okhttp3.internal.b.b("timeout", jLongValue, unit);
                    }
                    Long l2 = y.c;
                    if (l2 != null) {
                        long jLongValue2 = l2.longValue();
                        org.slf4j.b bVar3 = b0.a;
                        long j = jLongValue2 == Long.MAX_VALUE ? 0L : jLongValue2;
                        TimeUnit unit2 = TimeUnit.MILLISECONDS;
                        zVarB.c(j, unit2);
                        long j2 = jLongValue2 != Long.MAX_VALUE ? jLongValue2 : 0L;
                        Intrinsics.checkNotNullParameter(unit2, "unit");
                        zVarB.x = okhttp3.internal.b.b("timeout", j2, unit2);
                    }
                }
                return new okhttp3.A(zVarB);
            case 12:
                return ((io.ktor.utils.io.k) ((io.ktor.utils.io.t) this.receiver)).h((kotlin.coroutines.h) obj);
            default:
                ((l0) this.receiver).k((Throwable) obj);
                return Unit.a;
        }
    }
}
