package androidx.compose.foundation.text.input.internal;

import android.content.Intent;
import android.os.Build;
import android.view.View;
import androidx.compose.runtime.L0;
import androidx.compose.ui.platform.C0980z0;
import androidx.compose.ui.platform.ComposeView;
import androidx.datastore.core.P;
import androidx.datastore.core.a0;
import androidx.lifecycle.Y;
import androidx.paging.C1325l;
import androidx.paging.N;
import com.appsflyer.AppsFlyerLib;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3675m6;
import com.google.firebase.perf.metrics.Trace;
import com.google.firebase.sessions.C3999v;
import com.google.firebase.sessions.L;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.features.blocks.GamesActivity;
import com.quizlet.features.folders.data.G0;
import com.quizlet.features.folders.data.M0;
import com.quizlet.features.folders.data.N0;
import com.quizlet.features.folders.data.P0;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.features.onboarding.flashcards.OnboardingFlashcardsActivity;
import com.quizlet.features.onboarding.navigation.OnboardingNavigationActivity;
import com.quizlet.features.onboarding.survey.OnboardingSurveyActivity;
import com.quizlet.generated.enums.G1;
import com.quizlet.learn.viewmodel.G;
import com.quizlet.quizletandroid.databinding.C4609m;
import com.quizlet.quizletandroid.ui.studymodes.assistant.LearningAssistantActivity;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeActivity;
import com.quizlet.security.challenge.activity.SecurityChallengeActivity;
import com.sdk.growthbook.GrowthBookSDK;
import com.sdk.growthbook.model.GBValuesKt;
import io.reactivex.rxjava3.internal.operators.observable.C4899s;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.IndexedValue;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC5002j;
import kotlinx.coroutines.flow.s0;

/* renamed from: androidx.compose.foundation.text.input.internal.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0496b implements InterfaceC5002j {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ C0496b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(androidx.paging.N r5, kotlin.coroutines.h r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof androidx.paging.C1314f0
            if (r0 == 0) goto L13
            r0 = r6
            androidx.paging.f0 r0 = (androidx.paging.C1314f0) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            androidx.paging.f0 r0 = new androidx.paging.f0
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: kotlinx.coroutines.channels.ClosedSendChannelException -> L41
            goto L41
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r4.b     // Catch: kotlinx.coroutines.channels.ClosedSendChannelException -> L41
            androidx.paging.a1 r6 = (androidx.paging.a1) r6     // Catch: kotlinx.coroutines.channels.ClosedSendChannelException -> L41
            r0.l = r3     // Catch: kotlinx.coroutines.channels.ClosedSendChannelException -> L41
            kotlinx.coroutines.channels.h r6 = r6.a     // Catch: kotlinx.coroutines.channels.ClosedSendChannelException -> L41
            java.lang.Object r5 = r6.s(r5, r0)     // Catch: kotlinx.coroutines.channels.ClosedSendChannelException -> L41
            if (r5 != r1) goto L41
            return r1
        L41:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.input.internal.C0496b.a(androidx.paging.N, kotlin.coroutines.h):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x0066, code lost:
    
        if (r7.w(r6, r0) == r1) goto L22;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(kotlin.collections.IndexedValue r6, kotlin.coroutines.h r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof androidx.paging.C1311e
            if (r0 == 0) goto L13
            r0 = r7
            androidx.paging.e r0 = (androidx.paging.C1311e) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.paging.e r0 = new androidx.paging.e
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3a
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L69
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            kotlin.collections.IndexedValue r6 = r0.k
            androidx.compose.foundation.text.input.internal.b r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L53
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r5.b
            com.quizlet.remote.model.notes.e r7 = (com.quizlet.remote.model.notes.e) r7
            java.lang.Object r7 = r7.c
            kotlinx.coroutines.flow.d0 r7 = (kotlinx.coroutines.flow.d0) r7
            r0.j = r5
            r0.k = r6
            r0.n = r4
            java.lang.Object r7 = r7.emit(r6, r0)
            if (r7 != r1) goto L52
            goto L68
        L52:
            r2 = r5
        L53:
            java.lang.Object r7 = r2.b
            com.quizlet.remote.model.notes.e r7 = (com.quizlet.remote.model.notes.e) r7
            java.lang.Object r7 = r7.b
            androidx.appcompat.widget.z r7 = (androidx.appcompat.widget.C0122z) r7
            r2 = 0
            r0.j = r2
            r0.k = r2
            r0.n = r3
            java.lang.Object r6 = r7.w(r6, r0)
            if (r6 != r1) goto L69
        L68:
            return r1
        L69:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.input.internal.C0496b.b(kotlin.collections.IndexedValue, kotlin.coroutines.h):java.lang.Object");
    }

    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h hVar) {
        Object objE;
        String string;
        Object value;
        Object value2;
        kotlinx.collections.immutable.b bVarI;
        boolean z;
        String str;
        s0 s0Var;
        Object value3;
        String upperCase;
        Object objT;
        com.quizlet.ui.states.a aVar;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                u uVar = (u) obj2;
                if (Build.VERSION.SDK_INT >= 34) {
                    i.a.a(uVar.i(), (View) uVar.b);
                }
                return Unit.a;
            case 1:
                ((C0980z0) obj2).a.j(((Number) obj).floatValue());
                return Unit.a;
            case 2:
                P p = (P) obj2;
                return ((p.h.q() instanceof a0) || (objE = P.e(p, true, hVar)) != kotlin.coroutines.intrinsics.a.a) ? Unit.a : objE;
            case 3:
                return b((IndexedValue) obj, hVar);
            case 4:
                Object objS = ((kotlinx.coroutines.channels.x) obj2).s(obj, hVar);
                return objS == kotlin.coroutines.intrinsics.a.a ? objS : Unit.a;
            case 5:
                return a((N) obj, hVar);
            case 6:
                ((kotlinx.coroutines.channels.h) obj2).o((Unit) obj);
                return Unit.a;
            case 7:
                ((L0) ((androidx.paging.compose.d) obj2).e).setValue((C1325l) obj);
                return Unit.a;
            case 8:
                ((L) obj2).c.set((C3999v) obj);
                return Unit.a;
            case 9:
                Long l = (Long) obj;
                if (l == null || (string = l.toString()) == null) {
                    string = "";
                }
                ((AppsFlyerLib) obj2).setCustomerUserId(string);
                return Unit.a;
            case 10:
                if (!(((com.quizlet.features.blocks.data.a) obj) instanceof com.quizlet.features.blocks.data.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                String str2 = GamesActivity.l;
                GamesActivity gamesActivity = (GamesActivity) obj2;
                gamesActivity.getClass();
                Intent intent = new Intent();
                intent.putExtra("extra_start_learn", true);
                gamesActivity.setResult(-1, intent);
                gamesActivity.finish();
                return Unit.a;
            case 11:
                Object obj3 = ((kotlin.r) obj).a;
                com.quizlet.features.folders.viewmodel.N n = (com.quizlet.features.folders.viewmodel.N) obj2;
                if (!(obj3 instanceof kotlin.q)) {
                    List list = (List) obj3;
                    if (list.isEmpty()) {
                        do {
                            s0Var = n.w;
                            value3 = s0Var.getValue();
                        } while (!s0Var.k(value3, M0.a));
                    } else {
                        s0 s0Var2 = n.w;
                        do {
                            value2 = s0Var2.getValue();
                            P0 p0 = (P0) value2;
                            ArrayList arrayList = new ArrayList();
                            for (Object obj4 : list) {
                                if (!(((com.quizlet.ui.models.content.listitem.o) obj4) instanceof com.quizlet.ui.models.content.listitem.h)) {
                                    arrayList.add(obj4);
                                }
                            }
                            bVarI = AbstractC3409x1.i(arrayList);
                            z = list.size() >= 3;
                            com.quizlet.features.folders.data.L0 l0 = p0 instanceof com.quizlet.features.folders.data.L0 ? (com.quizlet.features.folders.data.L0) p0 : null;
                            str = l0 != null ? l0.c : null;
                            if ((8 & 2) != 0) {
                                z = false;
                            }
                            if ((8 & 4) != 0) {
                                str = null;
                            }
                        } while (!s0Var2.k(value2, new com.quizlet.features.folders.data.L0(bVarI, z, str, G0.b)));
                    }
                }
                Throwable thA = kotlin.r.a(obj3);
                if (thA != null) {
                    timber.log.c.a.c(thA, "Failed to load study materials", new Object[0]);
                    s0 s0Var3 = n.w;
                    do {
                        value = s0Var3.getValue();
                    } while (!s0Var3.k(value, N0.a));
                }
                return Unit.a;
            case 12:
                ((Number) obj).intValue();
                ((Function0) obj2).invoke();
                return Unit.a;
            case 13:
                com.quizlet.features.onboarding.navigation.k kVar = (com.quizlet.features.onboarding.navigation.k) obj;
                OnboardingNavigationActivity context = (OnboardingNavigationActivity) obj2;
                if (Intrinsics.b(kVar, com.quizlet.features.onboarding.navigation.h.a)) {
                    int i = OnboardingNavigationActivity.j;
                    Intrinsics.checkNotNullParameter(context, "context");
                    Intent intent2 = new Intent(context, (Class<?>) OnboardingFlashcardsActivity.class);
                    androidx.activity.result.b bVar = context.f;
                    if (bVar == null) {
                        Intrinsics.m("flashcardsAcknowledgeResultLauncher");
                        throw null;
                    }
                    bVar.a(intent2);
                } else if (Intrinsics.b(kVar, com.quizlet.features.onboarding.navigation.j.a)) {
                    int i2 = OnboardingNavigationActivity.j;
                    Intrinsics.checkNotNullParameter(context, "context");
                    Intent intent3 = new Intent(context, (Class<?>) OnboardingSurveyActivity.class);
                    androidx.activity.result.b bVar2 = context.g;
                    if (bVar2 == null) {
                        Intrinsics.m("surveyResultLauncher");
                        throw null;
                    }
                    bVar2.a(intent3);
                } else if (Intrinsics.b(kVar, com.quizlet.features.onboarding.navigation.i.a)) {
                    com.quizlet.features.infra.navigation.A a = context.i;
                    if (a == null) {
                        Intrinsics.m("upgradeNavigation");
                        throw null;
                    }
                    com.quizlet.features.infra.models.upgrade.a aVar2 = com.quizlet.features.infra.models.upgrade.a.w;
                    androidx.activity.result.b bVar3 = context.h;
                    if (bVar3 == null) {
                        Intrinsics.m("qPlusUpsellResultLauncher");
                        throw null;
                    }
                    a.i("delayed_signup_upsell", aVar2, bVar3);
                } else {
                    if (!(kVar instanceof com.quizlet.features.onboarding.navigation.g)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    com.quizlet.features.onboarding.navigation.g gVar = (com.quizlet.features.onboarding.navigation.g) kVar;
                    int i3 = OnboardingNavigationActivity.j;
                    Intent intent4 = new Intent();
                    intent4.putExtra("HasNewHomeData", gVar.a);
                    intent4.putExtra("UserUpgradeType", gVar.b);
                    context.setResult(-1, intent4);
                    context.finish();
                }
                return Unit.a;
            case 14:
                com.quizlet.features.questiontypes.basequestion.h hVar2 = (com.quizlet.features.questiontypes.basequestion.h) obj;
                com.quizlet.features.questiontypes.basequestion.i iVar = (com.quizlet.features.questiontypes.basequestion.i) obj2;
                if (hVar2 instanceof com.quizlet.features.questiontypes.basequestion.f) {
                    ((com.quizlet.features.questiontypes.basequestion.k) iVar).e.j(Boolean.valueOf(((com.quizlet.features.questiontypes.basequestion.f) hVar2).a));
                } else {
                    if (!(hVar2 instanceof com.quizlet.features.questiontypes.basequestion.g)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    com.quizlet.features.questiontypes.basequestion.data.b data = ((com.quizlet.features.questiontypes.basequestion.g) hVar2).a;
                    com.quizlet.features.questiontypes.basequestion.k kVar2 = (com.quizlet.features.questiontypes.basequestion.k) iVar;
                    kVar2.getClass();
                    Intrinsics.checkNotNullParameter(data, "data");
                    kVar2.f.j(data);
                }
                return Unit.a;
            case 15:
                Pair pair = (Pair) obj;
                Long l2 = (Long) pair.a;
                String str3 = (String) pair.b;
                com.quizlet.growthbook.e eVar = (com.quizlet.growthbook.e) obj2;
                String string2 = l2 != null ? l2.toString() : null;
                LinkedHashMap linkedHashMap = eVar.h;
                if (string2 == null) {
                    linkedHashMap.remove("user_id");
                } else {
                    linkedHashMap.put("user_id", GBValuesKt.toGbString(string2));
                }
                if (str3 != null) {
                    upperCase = str3.toUpperCase(Locale.ROOT);
                    Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
                } else {
                    upperCase = null;
                }
                if (upperCase == null) {
                    linkedHashMap.remove("country_code");
                } else {
                    linkedHashMap.put("country_code", GBValuesKt.toGbString(upperCase));
                }
                GrowthBookSDK growthBookSDK = eVar.g;
                if (growthBookSDK != null) {
                    growthBookSDK.setAttributes(V.l(linkedHashMap));
                    return Unit.a;
                }
                Intrinsics.m("growthBookSDK");
                throw null;
            case 16:
                com.quizlet.learn.data.onboarding.B b = (com.quizlet.learn.data.onboarding.B) obj;
                LearningAssistantActivity learningAssistantActivity = (LearningAssistantActivity) obj2;
                if (b instanceof com.quizlet.learn.data.onboarding.A) {
                    String str4 = LearningAssistantActivity.D;
                    ((ComposeView) learningAssistantActivity.t.getValue()).setVisibility(0);
                } else if (b instanceof com.quizlet.learn.data.onboarding.z) {
                    String str5 = LearningAssistantActivity.D;
                    G gB0 = learningAssistantActivity.b0();
                    gB0.z1 = true;
                    gB0.Q();
                } else if (Intrinsics.b(b, com.quizlet.learn.data.onboarding.w.a)) {
                    ((C4609m) learningAssistantActivity.K()).g.setVisibility(8);
                } else if (b instanceof com.quizlet.learn.data.onboarding.x) {
                    com.quizlet.learn.data.onboarding.x xVar = (com.quizlet.learn.data.onboarding.x) b;
                    int i4 = xVar.a;
                    String setTitle = xVar.c;
                    Intrinsics.checkNotNullParameter(setTitle, "setTitle");
                    G1 studyableType = xVar.e;
                    Intrinsics.checkNotNullParameter(studyableType, "studyableType");
                    String str6 = LearningAssistantActivity.D;
                    learningAssistantActivity.startActivity(WriteModeActivity.T(learningAssistantActivity, Integer.valueOf(i4), Long.valueOf(xVar.b), setTitle, Long.valueOf(xVar.d), studyableType, xVar.f));
                    learningAssistantActivity.finish();
                } else {
                    if (!(b instanceof com.quizlet.learn.data.onboarding.y)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    com.quizlet.learn.data.onboarding.y yVar = (com.quizlet.learn.data.onboarding.y) b;
                    int i5 = yVar.a;
                    String setTitle2 = yVar.c;
                    Intrinsics.checkNotNullParameter(setTitle2, "setTitle");
                    Intrinsics.checkNotNullParameter(yVar.e, "studyableType");
                    InterfaceC4176w0 meteredEvent = yVar.g;
                    Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
                    String str7 = LearningAssistantActivity.D;
                    learningAssistantActivity.startActivity(AbstractC3675m6.b(learningAssistantActivity, i5, new StudyableModelData.StudySet(yVar.b), setTitle2, yVar.d, yVar.f, 1, null, meteredEvent, false));
                    learningAssistantActivity.finish();
                }
                return Unit.a;
            case 17:
                return (((Boolean) obj).booleanValue() || (objT = ((androidx.camera.camera2.internal.concurrent.a) obj2).T(true, hVar)) != kotlin.coroutines.intrinsics.a.a) ? Unit.a : objT;
            case 18:
                if (!Intrinsics.b((com.quizlet.security.challenge.viewmodel.b) obj, com.quizlet.security.challenge.viewmodel.b.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                ((SecurityChallengeActivity) obj2).finish();
                return Unit.a;
            case 19:
                ((Trace) obj2).stop();
                return Unit.a;
            case 20:
                ((Function1) obj2).invoke(new Integer(((Number) obj).intValue()));
                return Unit.a;
            case 21:
                ((com.onetrust.otpublishers.headless.UI.TVUI.datautils.d) obj2).g = (com.quizlet.billing.model.b) obj;
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                Object objB = com.quizlet.upgrade.viewmodel.h.B((com.quizlet.upgrade.viewmodel.h) obj2, (com.quizlet.billing.model.b) obj, hVar);
                return objB == kotlin.coroutines.intrinsics.a.a ? objB : Unit.a;
            case EventType.AUDIO /* 23 */:
                Y y = ((com.quizlet.upgrade.viewmodel.n) obj2).e;
                boolean z2 = ((com.quizlet.billing.model.b) obj).f;
                if (z2) {
                    aVar = com.quizlet.ui.states.a.d;
                } else {
                    if (z2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    aVar = com.quizlet.ui.states.a.c;
                }
                y.j(aVar);
                return Unit.a;
            default:
                ((C4899s) obj2).c(obj);
                return Unit.a;
        }
    }

    public C0496b(kotlinx.coroutines.channels.x channel) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(channel, "channel");
        this.b = channel;
    }
}
