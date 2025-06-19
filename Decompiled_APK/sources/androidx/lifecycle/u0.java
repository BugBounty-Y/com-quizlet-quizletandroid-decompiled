package androidx.lifecycle;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.view.ViewGroup;
import android.webkit.WebSettings;
import androidx.compose.animation.C0282i;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.W0;
import androidx.compose.ui.platform.X0;
import androidx.compose.ui.text.C0985e;
import androidx.compose.ui.text.C0995g;
import androidx.navigation.C1265a;
import androidx.navigation.C1282d;
import androidx.navigation.compose.C1276i;
import com.braze.BrazeUser;
import com.braze.models.inappmessage.IInAppMessage;
import com.braze.ui.UserJavascriptInterfaceBase;
import com.braze.ui.actions.brazeactions.steps.SetCustomUserAttributeStep;
import com.braze.ui.actions.brazeactions.steps.StepData;
import com.braze.ui.inappmessage.BrazeInAppMessageManager;
import com.comscore.streaming.EventType;
import com.facebook.AccessToken;
import com.facebook.FacebookException;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_camera.H1;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.data.model.Chapter;
import com.quizlet.data.model.E0;
import com.quizlet.data.model.ExerciseDetails;
import com.quizlet.data.model.ExerciseGroup;
import com.quizlet.data.model.Section;
import com.quizlet.data.model.TableOfContentItem;
import com.quizlet.data.model.Textbook;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.diagrams.DiagramWebView;
import com.quizlet.diagrams.ui.DiagramJSBridge;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.features.revisioncenter.RevisionCenterLog;
import com.quizlet.eventlogger.features.revisioncenter.RevisionCenterSource;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.notes.common.events.C4372c;
import com.quizlet.features.notes.common.events.C4373d;
import com.quizlet.features.practicetest.detail.data.C4406i;
import com.quizlet.generated.enums.S0;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetActivity;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableText;
import com.skydoves.balloon.internals.DefinitionKt;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class u0 implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ u0(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        C lifecycle;
        ArrayList arrayList;
        String str;
        int i = 17;
        int i2 = 3;
        int i3 = 0;
        int i4 = 1;
        Object obj2 = this.c;
        Object obj3 = this.b;
        switch (this.a) {
            case 0:
                ((X) obj3).l(((Function1) obj2).invoke(obj));
                return Unit.a;
            case 1:
                androidx.navigation.L navOptions = (androidx.navigation.L) obj;
                Intrinsics.checkNotNullParameter(navOptions, "$this$navOptions");
                C1265a animBuilder = new C1265a(2);
                navOptions.getClass();
                Intrinsics.checkNotNullParameter(animBuilder, "animBuilder");
                C1282d c1282d = new C1282d();
                c1282d.a = -1;
                c1282d.b = -1;
                animBuilder.invoke(c1282d);
                int i5 = c1282d.a;
                androidx.navigation.J j = navOptions.a;
                j.g = i5;
                j.h = c1282d.b;
                androidx.navigation.B b = (androidx.navigation.B) obj3;
                if (b instanceof androidx.navigation.D) {
                    int i6 = androidx.navigation.B.e;
                    Iterator it2 = H1.b(b).iterator();
                    while (true) {
                        boolean zHasNext = it2.hasNext();
                        androidx.navigation.internal.j jVar = ((androidx.navigation.r) obj2).b;
                        if (zHasNext) {
                            androidx.navigation.B b2 = (androidx.navigation.B) it2.next();
                            androidx.navigation.B bG = jVar.g();
                            if (Intrinsics.b(b2, bG != null ? bG.c : null)) {
                            }
                        } else {
                            int i7 = androidx.navigation.D.g;
                            navOptions.a(I1.f(jVar.h()).b.c, new C1265a(i2));
                        }
                    }
                }
                return Unit.a;
            case 2:
                androidx.navigation.H h = (androidx.navigation.H) obj3;
                h.getClass();
                J owner = (J) obj2;
                Intrinsics.checkNotNullParameter(owner, "owner");
                Intrinsics.checkNotNullParameter(owner, "owner");
                androidx.navigation.internal.j jVar2 = h.b;
                jVar2.getClass();
                Intrinsics.checkNotNullParameter(owner, "owner");
                if (!Intrinsics.b(owner, jVar2.n)) {
                    J j2 = jVar2.n;
                    X0 x0 = jVar2.r;
                    if (j2 != null && (lifecycle = j2.getLifecycle()) != null) {
                        lifecycle.b(x0);
                    }
                    jVar2.n = owner;
                    owner.getLifecycle().a(x0);
                }
                return new androidx.navigation.compose.N();
            case 3:
                return new androidx.compose.animation.core.P(13, (W0) obj3, (C1276i) obj2);
            case 4:
                return UserJavascriptInterfaceBase.incrementCustomUserAttribute$lambda$24((String) obj3, (Integer) obj2, (BrazeUser) obj);
            case 5:
                return UserJavascriptInterfaceBase.setCustomUserAttributeArray$lambda$20((String) obj3, (String[]) obj2, (BrazeUser) obj);
            case 6:
                return SetCustomUserAttributeStep.run$lambda$1((StepData) obj3, obj2, (BrazeUser) obj);
            case 7:
                return Boolean.valueOf(BrazeInAppMessageManager.createBrazeUserChangeEventSubscriber$lambda$57$lambda$56((BrazeInAppMessageManager) obj3, (String) obj2, (IInAppMessage) obj));
            case 8:
                if (((Boolean) obj).booleanValue()) {
                    androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
                    if (fVar != null) {
                        fVar.r();
                    }
                } else {
                    if (((com.perimeterx.mobile_sdk.session.l) ((com.google.firebase.messaging.u) obj3).b) != null) {
                        String url = (String) obj2;
                        Intrinsics.checkNotNullParameter(url, "url");
                        try {
                            arrayList = new ArrayList();
                            com.perimeterx.mobile_sdk.session.d dVarB = com.perimeterx.mobile_sdk.session.l.b(new URL(url), com.perimeterx.mobile_sdk.business_logic.b.b);
                            if (dVarB != null) {
                                arrayList.addAll(dVarB.l(url));
                            }
                        } catch (Exception unused) {
                            arrayList = new ArrayList();
                        }
                    } else {
                        arrayList = null;
                    }
                    if (arrayList != null) {
                        new Handler(Looper.getMainLooper()).post(new com.google.firebase.crashlytics.internal.metadata.q(arrayList, 8));
                        androidx.constraintlayout.core.widgets.analyzer.f fVar2 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                        if (fVar2 != null) {
                            fVar2.r();
                        }
                    }
                }
                return Unit.a;
            case 9:
                androidx.compose.ui.graphics.S graphicsLayer = (androidx.compose.ui.graphics.S) obj;
                Intrinsics.checkNotNullParameter(graphicsLayer, "$this$graphicsLayer");
                W0 w0 = (W0) obj2;
                if (((com.quizlet.assembly.compose.components.flashcards.d) obj3) == com.quizlet.assembly.compose.components.flashcards.d.a) {
                    graphicsLayer.h(((Number) w0.getValue()).floatValue());
                } else {
                    graphicsLayer.i(((Number) w0.getValue()).floatValue());
                }
                graphicsLayer.d(graphicsLayer.s.a() * 12.0f);
                return Unit.a;
            case 10:
                String it3 = (String) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                Integer num = (Integer) obj3;
                Function1 function1 = (Function1) obj2;
                if (num != null && it3.length() > num.intValue()) {
                    String strSubstring = it3.substring(0, num.intValue());
                    Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                    function1.invoke(strSubstring);
                } else {
                    function1.invoke(it3);
                }
                return Unit.a;
            case 11:
                com.quizlet.assembly.compose.menu.o it4 = (com.quizlet.assembly.compose.menu.o) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                ((Function2) obj3).invoke(it4, (com.quizlet.assembly.compose.modals.x) obj2);
                return Unit.a;
            case 12:
                Context context = (Context) obj;
                Intrinsics.checkNotNullParameter(context, "context");
                DiagramWebView webView = new DiagramWebView(context);
                webView.setLayoutParams(new ViewGroup.LayoutParams(-1, -1));
                WebSettings settings = webView.getSettings();
                Intrinsics.checkNotNullExpressionValue(settings, "getSettings(...)");
                settings.setJavaScriptEnabled(true);
                DiagramJSBridge diagramJSBridge = (DiagramJSBridge) obj3;
                diagramJSBridge.getClass();
                Intrinsics.checkNotNullParameter(webView, "webView");
                diagramJSBridge.b = webView;
                webView.addJavascriptInterface(diagramJSBridge, "_diagram");
                webView.setWebViewClient(new com.facebook.internal.L((Function0) obj2, 4));
                return webView;
            case 13:
                ExplanationsEventLog.Payload createEvent = (ExplanationsEventLog.Payload) obj;
                int i8 = ExplanationsLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                TableOfContentItem tableOfContentItem = (TableOfContentItem) obj3;
                if (tableOfContentItem instanceof Chapter) {
                    str = "chapter";
                } else if (tableOfContentItem instanceof ExerciseGroup) {
                    str = DBGroup.TABLE_NAME;
                } else {
                    if (!(tableOfContentItem instanceof Section)) {
                        throw new IllegalArgumentException("Not a valid TableOfContentItem");
                    }
                    str = "section";
                }
                ExplanationsLogger.EventData.Textbook textbook = (ExplanationsLogger.EventData.Textbook) obj2;
                createEvent.h(textbook.getId(), Long.valueOf(tableOfContentItem.b()), textbook.getIsbn(), str);
                return Unit.a;
            case 14:
                RevisionCenterLog.Payload createEvent2 = (RevisionCenterLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent2, "$this$createEvent");
                createEvent2.setType(((S0) obj3).a());
                createEvent2.setSource(((RevisionCenterSource) obj2).getValue());
                return Unit.a;
            case 15:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                ((androidx.compose.foundation.text.z0) obj3).invoke((com.quizlet.explanations.myexplanations.data.g) obj2);
                return Unit.a;
            case 16:
                com.quizlet.data.model.U it5 = (com.quizlet.data.model.U) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                com.quizlet.explanations.textbook.exercisedetail.viewmodel.c cVar = (com.quizlet.explanations.textbook.exercisedetail.viewmodel.c) obj3;
                androidx.work.impl.model.c cVar2 = cVar.f;
                io.reactivex.rxjava3.core.p pVarO = io.reactivex.rxjava3.core.p.o(cVar2.r(), cVar2.t(), cVar.j.y(cVar2), com.quizlet.explanations.textbook.exercisedetail.viewmodel.a.a);
                Intrinsics.checkNotNullExpressionValue(pVarO, "zip(...)");
                io.reactivex.rxjava3.internal.observers.e eVarB = B7.b(pVarO, new com.quizlet.explanations.solution.fragments.b(1, cVar, com.quizlet.explanations.textbook.exercisedetail.viewmodel.c.class, "handleError", "handleError(Ljava/lang/Throwable;)V", 0, 19), new u0(i, it5, cVar));
                Intrinsics.checkNotNullParameter(eVarB, "<this>");
                cVar.A(eVarB);
                ExerciseDetails exerciseDetails = cVar.t;
                if (exerciseDetails != null) {
                    Textbook textbook2 = exerciseDetails.j;
                    cVar.e.d((String) obj2, new ExplanationsLogger.EventData.Exercise(textbook2.a, textbook2.b, exerciseDetails.b));
                }
                return Unit.a;
            case 17:
                kotlin.v vVar = (kotlin.v) obj;
                Intrinsics.checkNotNullParameter(vVar, "<destruct>");
                Object obj4 = vVar.a;
                Intrinsics.checkNotNullExpressionValue(obj4, "component1(...)");
                Object obj5 = vVar.b;
                Intrinsics.checkNotNullExpressionValue(obj5, "component2(...)");
                Boolean bool = (Boolean) obj5;
                Object obj6 = vVar.c;
                Intrinsics.checkNotNullExpressionValue(obj6, "component3(...)");
                Boolean bool2 = (Boolean) obj6;
                com.quizlet.data.model.U u = (com.quizlet.data.model.U) obj3;
                ExerciseDetails exercise = u.a;
                Intrinsics.checkNotNullParameter(exercise, "exercise");
                Textbook textbook3 = exercise.j;
                long j3 = textbook3.a;
                String str2 = textbook3.b;
                String str3 = exercise.b;
                com.quizlet.explanations.solution.data.g gVar = new com.quizlet.explanations.solution.data.g(j3, str2, str3);
                com.quizlet.explanations.textbook.exercisedetail.viewmodel.c cVar3 = (com.quizlet.explanations.textbook.exercisedetail.viewmodel.c) obj2;
                cVar3.t = exercise;
                com.quizlet.data.model.X x = u.b;
                cVar3.u = x;
                if (((Boolean) obj4).booleanValue()) {
                    com.quizlet.explanations.textbook.exercisedetail.viewmodel.c.C(cVar3, exercise, com.quizlet.explanations.solution.data.e.a, false, x, 8);
                } else if (u.c) {
                    com.quizlet.explanations.textbook.exercisedetail.viewmodel.c.C(cVar3, exercise, com.quizlet.explanations.solution.data.a.a, false, x, 8);
                } else {
                    List list = exercise.k;
                    if (x == null || !x.c) {
                        boolean zBooleanValue = bool.booleanValue();
                        Intrinsics.checkNotNullParameter(exercise, "exercise");
                        com.quizlet.explanations.textbook.exercisedetail.viewmodel.c.C(cVar3, exercise, new com.quizlet.explanations.solution.data.f(list, new com.quizlet.explanations.solution.data.g(textbook3.a, textbook3.b, str3)), zBooleanValue, x, 4);
                        cVar3.i.getClass();
                        long jA = com.quizlet.time.b.a();
                        Intrinsics.checkNotNullParameter(exercise, "<this>");
                        E0 e0 = new E0(exercise.a, exercise.b, exercise.c, exercise.d, exercise.f, exercise.e, jA, exercise.i, textbook3.a, textbook3.b, textbook3.c, textbook3.d, textbook3.f);
                        io.reactivex.rxjava3.internal.operators.completable.a aVar = new io.reactivex.rxjava3.internal.operators.completable.a(5, cVar3.f.n(), new com.quizlet.data.repository.widget.b(cVar3, false, e0, 19));
                        Intrinsics.checkNotNullExpressionValue(aVar, "flatMapCompletable(...)");
                        io.reactivex.rxjava3.disposables.b bVarC = B7.c(aVar, new androidx.navigation.U(e0, 21), null, 2);
                        Intrinsics.checkNotNullParameter(bVarC, "<this>");
                        cVar3.A(bVarC);
                    } else {
                        com.quizlet.explanations.textbook.exercisedetail.viewmodel.c.C(cVar3, exercise, new com.quizlet.explanations.solution.data.b(list, gVar, bool2.booleanValue()), false, x, 12);
                        ExplanationsLogger.MeteringPlacement placement = ExplanationsLogger.MeteringPlacement.b;
                        ExplanationsLogger explanationsLogger = cVar3.e;
                        explanationsLogger.getClass();
                        Intrinsics.checkNotNullParameter(placement, "placement");
                        ExplanationsEventLog.Companion companion = ExplanationsEventLog.b;
                        androidx.navigation.U u2 = new androidx.navigation.U(placement, 16);
                        companion.getClass();
                        explanationsLogger.a(ExplanationsEventLog.Companion.a("explanations_meter_exceeded", u2));
                    }
                }
                return Unit.a;
            case 18:
                Throwable it6 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                boolean z = it6 instanceof NoSuchElementException;
                Y y = ((com.quizlet.explanations.textbook.tableofcontents.viewmodel.b) obj3).m;
                if (z) {
                    timber.log.c.a.i(it6, android.support.v4.media.session.a.t(new StringBuilder("Textbook with isbn ("), (String) obj2, ") does not exist"), new Object[0]);
                    y.j(com.quizlet.uicommon.ui.states.a.c);
                } else {
                    y.j(com.quizlet.uicommon.ui.states.a.b);
                }
                return Unit.a;
            case 19:
                FacebookException it7 = (FacebookException) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                Date date = AccessToken.l;
                com.facebook.f.f.o().c(null, true);
                com.google.android.gms.internal.mlkit_vision_common.E.c(null);
                com.facebook.h.f.u().a(null, true);
                SharedPreferences.Editor editorEdit = ((com.facebook.login.B) obj3).a.edit();
                editorEdit.putBoolean("express_login_allowed", false);
                editorEdit.apply();
                ((Function1) obj2).invoke(it7);
                return Unit.a;
            case 20:
                androidx.compose.runtime.H DisposableEffect = (androidx.compose.runtime.H) obj;
                Intrinsics.checkNotNullParameter(DisposableEffect, "$this$DisposableEffect");
                com.quizlet.features.flashcards.screens.d dVar = new com.quizlet.features.flashcards.screens.d();
                J j4 = (J) obj3;
                j4.getLifecycle().a(dVar);
                return new C0282i((Function0) obj2, j4, dVar, i2);
            case 21:
                ((Function1) obj2).invoke(((StudiableText) obj3).a);
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                ((Function1) obj2).invoke(new com.quizlet.features.folders.addtofolder.data.m((com.quizlet.features.folders.addtofolder.data.t) ((com.quizlet.features.folders.addtofolder.data.u) obj3).l.get(((Integer) obj).intValue())));
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                int iIntValue = ((Integer) obj).intValue();
                C0995g c0995g = (C0995g) obj3;
                Function1 function12 = (Function1) obj2;
                if (((C0985e) CollectionsKt.firstOrNull(c0995g.c(iIntValue, iIntValue, "helpCenter"))) != null) {
                    function12.invoke(C4372c.a);
                }
                if (((C0985e) CollectionsKt.firstOrNull(c0995g.c(iIntValue, iIntValue, "termsOfService"))) != null) {
                    function12.invoke(C4373d.a);
                }
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar = (com.quizlet.quizletandroid.ui.navigationmanagers.e) ((com.quizlet.features.notes.manager.a) obj3);
                eVar.getClass();
                int i9 = EditSetActivity.M;
                Intent intent = new Intent(eVar.a, (Class<?>) EditSetActivity.class);
                intent.putExtra("addMaterialFolderData", (AddMaterialFolderData) obj);
                Intrinsics.checkNotNullExpressionValue(intent, "buildCreateSetIntentFromFolder(...)");
                eVar.b(intent);
                ((Function0) obj2).invoke();
                return Unit.a;
            case EventType.SUBS /* 25 */:
                androidx.compose.foundation.lazy.g LazyColumn = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, com.quizlet.features.practicetest.common.composables.b.a, 3);
                kotlinx.collections.immutable.e eVar2 = (kotlinx.collections.immutable.e) obj3;
                LazyColumn.q(eVar2.size(), new androidx.compose.ui.viewinterop.b(i, new C4237k(26), eVar2), new com.quizlet.features.practicetest.common.composables.j(eVar2, 0), new androidx.compose.runtime.internal.d(true, -632812321, new com.quizlet.features.practicetest.common.composables.k(eVar2, (Function1) obj2, i3)));
                return Unit.a;
            case EventType.CDN /* 26 */:
                Boolean bool3 = (Boolean) obj;
                boolean zBooleanValue2 = bool3.booleanValue();
                ((InterfaceC0773a0) obj2).setValue(bool3);
                ((com.quizlet.features.practicetest.detail.viewmodel.i) ((com.quizlet.features.practicetest.detail.viewmodel.a) obj3)).C(new C4406i(zBooleanValue2));
                return Unit.a;
            case 27:
                androidx.compose.foundation.lazy.g LazyColumn2 = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn2, "$this$LazyColumn");
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.q();
                float f = com.quizlet.ui.resources.designsystem.generated.j.i;
                mVar.p();
                float f2 = com.quizlet.ui.resources.designsystem.generated.j.j;
                mVar.s();
                float f3 = com.quizlet.ui.resources.designsystem.generated.j.h;
                mVar.s();
                com.quizlet.features.practicetest.results.data.t tVar = (com.quizlet.features.practicetest.results.data.t) obj3;
                androidx.compose.foundation.lazy.g.p(LazyColumn2, null, new androidx.compose.runtime.internal.d(true, 32362328, new com.quizlet.assembly.compose.input.m(28, tVar.a, AbstractC0382e.x(nVar, f3, f, f3, f2))), 3);
                mVar.s();
                mVar.s();
                mVar.t();
                androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, f3, DefinitionKt.NO_Float_VALUE, f3, com.quizlet.ui.resources.designsystem.generated.j.k, 2);
                List list2 = tVar.b;
                LazyColumn2.q(list2.size(), null, new com.quizlet.assembly.compose.menu.e(list2, 9), new androidx.compose.runtime.internal.d(true, -1091073711, new com.quizlet.features.folders.composables.V(list2, qVarY, (Function2) obj2, i4)));
                return Unit.a;
            case 28:
                StudiableImage image = (StudiableImage) obj;
                Intrinsics.checkNotNullParameter(image, "image");
                ((InterfaceC0773a0) obj2).setValue(image.a());
                com.quizlet.assembly.compose.modals.x.d((com.quizlet.assembly.compose.modals.x) obj3);
                return Unit.a;
            default:
                String it8 = (String) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                ((com.quizlet.features.questiontypes.written.ui.i) obj3).h.invoke(it8);
                ((InterfaceC0773a0) obj2).setValue(it8);
                return Unit.a;
        }
    }

    public /* synthetic */ u0(int i, Object obj, Function1 function1) {
        this.a = i;
        this.c = function1;
        this.b = obj;
    }
}
