package com.quizlet.login.magiclink.ui;

import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.view.ViewGroup;
import androidx.lifecycle.J;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.Yh;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.quizlet.data.model.EnumC4167t0;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBGroupSetFields;
import com.quizlet.diagrams.layoutmanager.DiagramCardLayoutManager;
import com.quizlet.eventlogger.features.achievements.AchievementsEventLogger;
import com.quizlet.eventlogger.model.NavigationEventLog;
import com.quizlet.generated.enums.EnumC4525u1;
import com.quizlet.generated.enums.H;
import com.quizlet.generated.enums.S0;
import com.quizlet.generated.enums.W;
import com.quizlet.learn.data.M;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.t;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.ActivityCenterFragment;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.ActivityCenterModalFragment;
import com.quizlet.quizletandroid.ui.diagramming.DiagramOverviewFragment;
import com.quizlet.quizletandroid.ui.group.classcontent.ClassContentListFragment;
import com.quizlet.quizletandroid.ui.joincontenttofolder.JoinContentToFolderActivity;
import com.quizlet.quizletandroid.ui.learnpaywall.LearnPaywallFragment;
import com.quizlet.quizletandroid.ui.login.BaseSignupFragment;
import com.quizlet.quizletandroid.ui.login.ParentEmailFragment;
import com.quizlet.quizletandroid.ui.login.SignUpWallModalFragment;
import com.quizlet.quizletandroid.ui.profile.ProfileUserClassListFragment;
import com.quizlet.quizletandroid.ui.setpage.addset.AddSetToClassActivity;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4740i;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import com.quizlet.quizletandroid.ui.studymodes.assistant.LearningAssistantActivity;
import com.skydoves.balloon.ArrowOrientationRules;
import com.skydoves.balloon.ArrowPositionRules;
import com.skydoves.balloon.Balloon;
import com.skydoves.balloon.BalloonAnimation;
import java.io.Serializable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.C4933y;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ e(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() throws ParseException {
        Object value;
        ArrayList arrayList;
        List listO;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                String str = MagicLinkLogOutDialogFragment.x;
                Serializable serializable = ((MagicLinkLogOutDialogFragment) obj).requireArguments().getSerializable("ARG_LOGOUT_WARNING");
                objValueOf = serializable instanceof EnumC4167t0 ? (EnumC4167t0) serializable : null;
                if (objValueOf != null) {
                    return objValueOf;
                }
                throw new IllegalStateException("No logout warning provided");
            case 1:
                String str2 = MagicLinkSwitchAccountDialogFragment.x;
                String string = ((MagicLinkSwitchAccountDialogFragment) obj).requireArguments().getString("ARG_MAGIC_LINK_CODE");
                if (string != null) {
                    return string;
                }
                throw new IllegalArgumentException("No magic link code provided");
            case 2:
                return ((com.quizlet.data.interactor.achievements.f) obj).m();
            case 3:
                return ((com.quizlet.quizletandroid.config.b) obj).a.m();
            case 4:
                com.quizlet.quizletandroid.config.d dVar = (com.quizlet.quizletandroid.config.d) obj;
                dVar.getClass();
                List list = dVar.a;
                ArrayList arrayList2 = new ArrayList(C.q(list, 10));
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    arrayList2.add(Pattern.compile((String) it2.next()));
                }
                return arrayList2;
            case 5:
                return (io.reactivex.rxjava3.disposables.a) ((t) ((Yh) obj).n).get();
            case 6:
                String str3 = ActivityCenterFragment.n;
                return Boolean.valueOf(((ActivityCenterFragment) obj).requireArguments().getBoolean("ARG_SHOULD_SHOW_TOOLBAR", true));
            case 7:
                String str4 = ActivityCenterModalFragment.K;
                return ((ActivityCenterModalFragment) obj).getString(R.string.activity_center_title);
            case 8:
                return (io.reactivex.rxjava3.disposables.a) ((com.quizlet.quizletandroid.ui.base.h) obj).b.get();
            case 9:
                ((androidx.compose.ui.focus.p) obj).b();
                return Unit.a;
            case 10:
                ((com.pubmatic.sdk.openwrap.banner.c) obj).destroy();
                return Unit.a;
            case 11:
                return (Map) obj;
            case 12:
                Context contextRequireContext = ((DiagramOverviewFragment) obj).requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                return new DiagramCardLayoutManager(contextRequireContext, 0);
            case 13:
                s0 s0Var = ((com.quizlet.quizletandroid.ui.globalnav.viewmodel.e) obj).f;
                do {
                    value = s0Var.getValue();
                } while (!s0Var.k(value, null));
                return Unit.a;
            case 14:
                String str5 = ClassContentListFragment.n;
                androidx.lifecycle.viewmodel.c defaultViewModelCreationExtras = ((ClassContentListFragment) obj).requireParentFragment().getDefaultViewModelCreationExtras();
                Intrinsics.checkNotNullExpressionValue(defaultViewModelCreationExtras, "<get-defaultViewModelCreationExtras>(...)");
                return defaultViewModelCreationExtras;
            case 15:
                com.quizlet.quizletandroid.ui.joincontenttofolder.k kVar = ((JoinContentToFolderActivity) obj).q;
                if (kVar != null) {
                    kVar.t.j(Boolean.FALSE);
                    return Unit.a;
                }
                Intrinsics.m("viewModel");
                throw null;
            case 16:
                com.onetrust.otpublishers.headless.UI.viewmodel.c cVar = ((LearnPaywallFragment) obj).f;
                if (cVar != null) {
                    return cVar;
                }
                Intrinsics.m("viewModelFactory");
                throw null;
            case 17:
                BaseSignupFragment baseSignupFragment = (BaseSignupFragment) obj;
                if (baseSignupFragment.k == null) {
                    Intrinsics.m("tooltipFactory");
                    throw null;
                }
                Context context = baseSignupFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
                J viewLifecycleOwner = baseSignupFragment.getViewLifecycleOwner();
                Object[] args = new Object[0];
                Intrinsics.checkNotNullParameter(args, "args");
                com.quizlet.qutils.string.f stringResData = new com.quizlet.qutils.string.f(R.string.signup_birthdate_tooltip, C4933y.P(args));
                com.quizlet.qutils.android.f block = new com.quizlet.qutils.android.f(26);
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(stringResData, "stringResData");
                Intrinsics.checkNotNullParameter(block, "block");
                Balloon.Builder builder = new Balloon.Builder(context);
                builder.m112setText((CharSequence) AbstractC3053s1.e(stringResData, context));
                builder.m80setLifecycleOwner(viewLifecycleOwner);
                builder.setVisibleArrow(true);
                builder.setArrowSizeResource(R.dimen.assembly_tooltip_arrow_size);
                builder.m46setArrowPositionRules(ArrowPositionRules.ALIGN_ANCHOR);
                builder.m44setArrowOrientationRules(ArrowOrientationRules.ALIGN_ANCHOR);
                Typeface typefaceA = androidx.core.content.res.k.a(context, com.quizlet.ui.resources.designsystem.generated.a.b);
                if (typefaceA != null) {
                    builder.setTextTypeface(typefaceA);
                }
                builder.setTextSizeResource(R.dimen.assembly_tooltip_text_size);
                builder.m113setTextColor(com.quizlet.themes.extensions.a.a(context, R.attr.AssemblyPrimaryActionText));
                builder.setPaddingResource(R.dimen.ref_spacing_small);
                builder.m51setBackgroundColor(com.quizlet.themes.extensions.a.a(context, R.attr.AssemblyTooltipBackground));
                builder.setCornerRadiusResource(R.dimen.ref_radius_medium);
                builder.m53setBalloonAnimation(BalloonAnimation.FADE);
                builder.setVisibleOverlay(false);
                builder.m65setDismissWhenTouchOutside(true);
                builder.m60setDismissWhenClicked(true);
                block.invoke(builder);
                return builder.build();
            case 18:
                String str6 = ParentEmailFragment.n;
                Serializable serializable2 = ((ParentEmailFragment) obj).requireArguments().getSerializable("requestType");
                Intrinsics.e(serializable2, "null cannot be cast to non-null type com.quizlet.login.oldlogin.LaunchParentEmailFragment.RequestType");
                return (com.quizlet.login.oldlogin.b) serializable2;
            case 19:
                String str7 = SignUpWallModalFragment.X;
                return (Intent) ((SignUpWallModalFragment) obj).requireArguments().getParcelable("redirectIntent");
            case 20:
                return Long.valueOf(((ProfileUserClassListFragment) obj).requireArguments().getLong("user_id", 0L));
            case 21:
                com.quizlet.quizletandroid.ui.setcreation.activities.d dVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.d) obj;
                dVar2.l.j(Boolean.FALSE);
                dVar2.D.setEnabled(false);
                dVar2.C.setVisibility(0);
                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = dVar2.B.A;
                if (fVar != null && (arrayList = fVar.p) != null) {
                    Collections.unmodifiableList(arrayList);
                }
                dVar2.y.e(dVar2.r);
                dVar2.finish();
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                ((ViewGroup) obj).setVisibility(0);
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                String str8 = AddSetToClassActivity.s;
                long[] longArrayExtra = ((AddSetToClassActivity) obj).getIntent().getLongArrayExtra("setsIds");
                return (longArrayExtra == null || (listO = C4933y.O(longArrayExtra)) == null) ? K.a : listO;
            case EventType.VIDEO /* 24 */:
                com.quizlet.quizletandroid.ui.setpage.addset.c cVar2 = (com.quizlet.quizletandroid.ui.setpage.addset.c) obj;
                com.quizlet.quizletandroid.util.a aVar = cVar2.d;
                LinkedHashSet setsIds = cVar2.f;
                aVar.getClass();
                Intrinsics.checkNotNullParameter(setsIds, "setsIds");
                com.quizlet.quizletandroid.util.e eVar = aVar.b;
                eVar.getClass();
                Intrinsics.checkNotNullParameter(setsIds, "setsIds");
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.GROUP_SET);
                bVar.c(DBGroupSetFields.SET, setsIds, null);
                bVar.c(DBGroupSetFields.GROUP, eVar.c, null);
                com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
                Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
                return aVarA;
            case EventType.SUBS /* 25 */:
                com.quizlet.quizletandroid.ui.startpage.nav2.adapters.e eVar2 = (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.e) obj;
                L l = eVar2.c;
                if (l != null) {
                    l.p.h(C4740i.a);
                }
                com.quizlet.features.achievements.home.a aVar2 = eVar2.d;
                if (aVar2 != null) {
                    AchievementsEventLogger achievementsEventLogger = aVar2.b;
                    achievementsEventLogger.getClass();
                    achievementsEventLogger.a(NavigationEventLog.Companion.b(NavigationEventLog.b, true, EnumC4525u1.HOMESCREEN.a(), "achievements_progress_module_clicked", W.BROWSE.a()));
                }
                return Unit.a;
            case EventType.CDN /* 26 */:
                ((com.quizlet.quizletandroid.ui.startpage.nav2.pushnotification.c) obj).H(false, false);
                return Unit.a;
            case 27:
                S0 s0 = S0.AUSTRALIA_HSC;
                H h = H.AUSTRALIA;
                com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a aVar3 = new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a(s0, h, new IntRange(14, 20, 1), null, 8);
                com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a aVar4 = new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a(S0.AUSTRALIA_VCE, h, new IntRange(14, 21, 1), null, 8);
                S0 s02 = S0.BRAZIL_ENEM;
                H h2 = H.BRAZIL;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k) obj).getClass();
                Locale locale = Locale.US;
                Date date = new SimpleDateFormat("MM-dd-yyyy", locale).parse("11-04-2024");
                Long lValueOf = date != null ? Long.valueOf(date.getTime()) : null;
                Date date2 = new SimpleDateFormat("MM-dd-yyyy", locale).parse("11-11-2024");
                Long lValueOf2 = date2 != null ? Long.valueOf(date2.getTime()) : null;
                if (lValueOf != null && lValueOf2 != null) {
                    long jCurrentTimeMillis = System.currentTimeMillis();
                    if (jCurrentTimeMillis < lValueOf.longValue()) {
                        objValueOf = Integer.valueOf((int) TimeUnit.MILLISECONDS.toDays(lValueOf.longValue() - jCurrentTimeMillis));
                    } else if (jCurrentTimeMillis < lValueOf2.longValue()) {
                        objValueOf = Integer.valueOf((int) TimeUnit.MILLISECONDS.toDays(lValueOf2.longValue() - jCurrentTimeMillis));
                    }
                }
                com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a aVar5 = new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a(s02, h2, null, objValueOf, 4);
                S0 s03 = S0.ENGLAND_GCSE;
                H h3 = H.GREAT_BRITAIN;
                com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a aVar6 = new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a(s03, h3, new IntRange(12, 18, 1), null, 8);
                com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a aVar7 = new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a(S0.ENGLAND_A_LEVELS, h3, new IntRange(15, 20, 1), null, 8);
                com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a aVar8 = new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a(S0.GERMANY_ABITUR, H.GERMANY, new IntRange(14, 20, 1), null, 8);
                S0 s04 = S0.INDIA_CSE;
                H h4 = H.INDIA;
                return B.j(aVar3, aVar4, aVar5, aVar6, aVar7, aVar8, new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a(s04, h4, new IntRange(22, 32, 1), null, 8), new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a(S0.INDIA_JEE, h4, new IntRange(16, 21, 1), null, 8), new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a(S0.INDIA_NEET, h4, new IntRange(16, 21, 1), null, 8), new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a(S0.MEXICO_EXANI, H.MEXICO, new IntRange(16, 19, 1), null, 8), new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.a(S0.POLAND_MATURA, H.POLAND, new IntRange(15, 21, 1), null, 8));
            case 28:
                ((com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.b) obj).d.invoke();
                return Unit.a;
            default:
                String str9 = LearningAssistantActivity.D;
                ((M) obj).getClass();
                return Unit.a;
        }
    }
}
