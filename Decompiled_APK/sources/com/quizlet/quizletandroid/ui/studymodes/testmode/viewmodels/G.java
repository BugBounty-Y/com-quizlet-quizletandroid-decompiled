package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import assistantMode.refactored.types.AssistantGradingSettings;
import assistantMode.refactored.types.StudiableData;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3097a5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3398u2;
import com.google.android.gms.internal.mlkit_vision_camera.H2;
import com.quizlet.data.model.C4179x0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.db.data.orm.Filter;
import com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger;
import com.quizlet.eventlogger.features.studymodes.test.TestEventLog;
import com.quizlet.eventlogger.features.studymodes.test.TestPayload;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.infra.studysetting.data.TestStudyModeConfig;
import com.quizlet.generated.enums.P;
import com.quizlet.shared.models.api.metering.MeteredEvent;
import com.quizlet.studiablemodels.StudiableMeteringData;
import com.quizlet.studiablemodels.StudiableQuestion;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.U;
import kotlin.collections.a0;
import kotlin.jvm.internal.Intrinsics;
import org.koin.core.error.DefinitionOverrideException;
import org.koin.core.error.KoinAppAlreadyStartedException;

@Metadata
/* loaded from: classes3.dex */
public final class G extends com.quizlet.viewmodel.b {
    public final Y A;
    public int B;
    public final String C;
    public final com.quizlet.features.infra.basestudy.manager.f D;
    public TestStudyModeConfig E;
    public boolean F;
    public boolean G;
    public boolean H;
    public InterfaceC4176w0 I;
    public InterfaceC4176w0 J;
    public DBSession K;
    public boolean L;
    public final m0 c;
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.c d;
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.e e;
    public final com.quizlet.data.interactor.school.b f;
    public final com.quizlet.infra.legacysyncengine.net.f g;
    public final com.quizlet.quizletandroid.managers.audio.h h;
    public final com.quizlet.time.b i;
    public final long j;
    public final com.quizlet.featuregate.features.flexiblegrading.a k;
    public final androidx.work.impl.model.c l;
    public final com.quizlet.infra.legacysyncengine.features.properties.d m;
    public final com.quizlet.features.infra.basestudy.usecase.b n;
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.logging.a o;
    public final com.quizlet.features.questiontypes.grading.a p;
    public final com.quizlet.data.repository.searchexplanations.c q;
    public final com.quizlet.data.connectivity.a r;
    public final Y s;
    public final Y t;
    public final X u;
    public final Y v;
    public final X w;
    public final X x;
    public final Y y;
    public final Y z;

    public G(m0 savedStateHandle, com.quizlet.features.infra.basestudy.manager.a studyModeManagerFactory, com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.c testStudyEngine, com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.e testManager, com.quizlet.data.interactor.school.b saveMeteringInfoUseCase, StudyModeMeteringEventLogger meteringLogger, com.quizlet.infra.legacysyncengine.net.f syncDispatcher, com.quizlet.quizletandroid.managers.audio.h audioManager, com.quizlet.featuregate.features.flexiblegrading.a smartGradingInTest, androidx.work.impl.model.c userProperties, com.quizlet.infra.legacysyncengine.features.properties.d studySetProperties, com.quizlet.features.infra.basestudy.usecase.b getLearnNavigationUseCase, com.quizlet.quizletandroid.ui.studymodes.testmode.logging.a testEventLogger, com.quizlet.features.questiontypes.grading.a smartGradingLogger, com.quizlet.data.repository.searchexplanations.c getStudiableMetadataUseCase, com.quizlet.data.connectivity.a networkConnectivityManager) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(studyModeManagerFactory, "studyModeManagerFactory");
        Intrinsics.checkNotNullParameter(testStudyEngine, "testStudyEngine");
        Intrinsics.checkNotNullParameter(testManager, "testManager");
        Intrinsics.checkNotNullParameter(saveMeteringInfoUseCase, "saveMeteringInfoUseCase");
        Intrinsics.checkNotNullParameter(meteringLogger, "meteringLogger");
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        Intrinsics.checkNotNullParameter(audioManager, "audioManager");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        Intrinsics.checkNotNullParameter(smartGradingInTest, "smartGradingInTest");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(studySetProperties, "studySetProperties");
        Intrinsics.checkNotNullParameter(getLearnNavigationUseCase, "getLearnNavigationUseCase");
        Intrinsics.checkNotNullParameter(testEventLogger, "testEventLogger");
        Intrinsics.checkNotNullParameter(smartGradingLogger, "smartGradingLogger");
        Intrinsics.checkNotNullParameter(getStudiableMetadataUseCase, "getStudiableMetadataUseCase");
        Intrinsics.checkNotNullParameter(networkConnectivityManager, "networkConnectivityManager");
        this.c = savedStateHandle;
        this.d = testStudyEngine;
        this.e = testManager;
        this.f = saveMeteringInfoUseCase;
        this.g = syncDispatcher;
        this.h = audioManager;
        this.i = timeProvider;
        this.j = 3000L;
        this.k = smartGradingInTest;
        this.l = userProperties;
        this.m = studySetProperties;
        this.n = getLearnNavigationUseCase;
        this.o = testEventLogger;
        this.p = smartGradingLogger;
        this.q = getStudiableMetadataUseCase;
        this.r = networkConnectivityManager;
        this.s = new Y();
        this.t = new Y();
        this.u = new X(1);
        this.v = new Y();
        this.w = new X(1);
        this.x = new X(1);
        this.y = new Y();
        this.z = new Y();
        this.A = new Y();
        this.C = androidx.compose.ui.node.B.f("toString(...)");
        com.quizlet.features.infra.basestudy.manager.f fVarA = studyModeManagerFactory.a(savedStateHandle);
        this.D = fVarA;
        com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = fVarA.x;
        DBSession dBSession = aVar.C;
        dBSession = (dBSession != null ? dBSession.getEndedTimestampMs() : 0L) <= 0 ? null : dBSession;
        this.K = dBSession;
        long localId = dBSession != null ? dBSession.getLocalId() : 0L;
        aVar.E = localId != 0 ? a0.c(new Filter(Long.valueOf(localId), DBSessionFields.LOCAL_ID)) : a0.c(new Filter((Long) 0L, (ModelField) DBSessionFields.MODE_TYPE));
        com.quizlet.infra.legacysyncengine.features.properties.d.c(studySetProperties, fVarA.u);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new v(this, null), 3);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x001c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.io.Serializable B(com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G r17, java.util.ArrayList r18, java.util.List r19, java.util.List r20, kotlin.coroutines.jvm.internal.c r21) throws java.lang.Throwable {
        /*
            r0 = r17
            r1 = r19
            r2 = r21
            r0.getClass()
            boolean r3 = r2 instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.w
            if (r3 == 0) goto L1c
            r3 = r2
            com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.w r3 = (com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.w) r3
            int r4 = r3.p
            r5 = -2147483648(0xffffffff80000000, float:-0.0)
            r6 = r4 & r5
            if (r6 == 0) goto L1c
            int r4 = r4 - r5
            r3.p = r4
            goto L21
        L1c:
            com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.w r3 = new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.w
            r3.<init>(r0, r2)
        L21:
            java.lang.Object r2 = r3.n
            kotlin.coroutines.intrinsics.a r4 = kotlin.coroutines.intrinsics.a.a
            int r5 = r3.p
            r6 = 1
            if (r5 == 0) goto L47
            if (r5 != r6) goto L3f
            java.util.ArrayList r0 = r3.m
            java.util.ArrayList r1 = r3.l
            java.util.List r4 = r3.k
            java.util.List r3 = r3.j
            androidx.glance.appwidget.protobuf.Z.e(r2)
            r16 = r2
            r2 = r1
            r1 = r4
            r4 = r16
            goto Ld9
        L3f:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L47:
            androidx.glance.appwidget.protobuf.Z.e(r2)
            java.util.ArrayList r2 = new java.util.ArrayList
            r5 = 10
            int r7 = kotlin.collections.C.q(r1, r5)
            r2.<init>(r7)
            java.util.Iterator r7 = r1.iterator()
        L59:
            boolean r8 = r7.hasNext()
            if (r8 == 0) goto L84
            java.lang.Object r8 = r7.next()
            com.quizlet.db.data.models.persisted.DBDiagramShape r8 = (com.quizlet.db.data.models.persisted.DBDiagramShape) r8
            java.lang.String r9 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r9)
            assistantMode.types.h r10 = new assistantMode.types.h
            long r11 = r8.getSetId()
            java.lang.String r15 = r8.getShape()
            java.lang.String r9 = "getShape(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r15, r9)
            long r13 = r8.getTermId()
            r10.<init>(r11, r13, r15)
            r2.add(r10)
            goto L59
        L84:
            java.util.ArrayList r7 = new java.util.ArrayList
            r8 = r20
            int r5 = kotlin.collections.C.q(r8, r5)
            r7.<init>(r5)
            java.util.Iterator r5 = r8.iterator()
        L93:
            boolean r8 = r5.hasNext()
            if (r8 == 0) goto Lb0
            java.lang.Object r8 = r5.next()
            com.quizlet.db.data.models.persisted.DBImageRef r8 = (com.quizlet.db.data.models.persisted.DBImageRef) r8
            com.quizlet.db.data.models.persisted.DBImage r8 = r8.getImage()
            java.lang.String r9 = "getImage(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r9)
            assistantMode.types.k r8 = com.quizlet.features.infra.basestudy.utils.b.b(r8)
            r7.add(r8)
            goto L93
        Lb0:
            com.quizlet.features.infra.basestudy.manager.f r5 = r0.D
            long r8 = r5.u
            r5 = r18
            r3.j = r5
            r3.k = r1
            r3.l = r2
            r3.m = r7
            r3.p = r6
            com.quizlet.data.repository.searchexplanations.c r0 = r0.q
            r0.getClass()
            com.quizlet.features.infra.basestudy.usecase.c r6 = new com.quizlet.features.infra.basestudy.usecase.c
            r10 = 0
            r6.<init>(r0, r8, r10)
            java.lang.Object r0 = r0.c
            kotlinx.coroutines.y r0 = (kotlinx.coroutines.AbstractC5040y) r0
            java.lang.Object r0 = kotlinx.coroutines.E.J(r0, r6, r3)
            if (r0 != r4) goto Ld6
            return r4
        Ld6:
            r4 = r0
            r3 = r5
            r0 = r7
        Ld9:
            java.util.Map r4 = (java.util.Map) r4
            com.quizlet.features.infra.basestudy.utils.c r5 = com.quizlet.features.infra.basestudy.utils.c.a
            assistantMode.refactored.types.StudiableData r1 = r5.a(r3, r1, r4)
            kotlin.v r3 = new kotlin.v
            r3.<init>(r1, r2, r0)
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G.B(com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G, java.util.ArrayList, java.util.List, java.util.List, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public static void H(G g, TestStudyModeConfig config) {
        g.getClass();
        Intrinsics.checkNotNullParameter(config, "config");
        g.E = config;
        io.reactivex.rxjava3.disposables.b bVarU = g.D.c().u(new com.quizlet.billing.manager.b(23, g, config), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
        Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
        Intrinsics.checkNotNullParameter(bVarU, "<this>");
        g.A(bVarU);
    }

    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.c C(StudiableData studiableData, List diagramShapes, List images, boolean z, boolean z2) throws DefinitionOverrideException, KoinAppAlreadyStartedException {
        P p = P.TEST_SUBMISSION;
        InterfaceC4176w0 interfaceC4176w0 = this.I;
        if (interfaceC4176w0 == null) {
            Intrinsics.m("testMeteredEvent");
            throw null;
        }
        Map meteringData = U.b(new Pair(p, interfaceC4176w0));
        com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.c cVar = this.d;
        cVar.getClass();
        Intrinsics.checkNotNullParameter(studiableData, "studiableData");
        Intrinsics.checkNotNullParameter(diagramShapes, "diagramShapes");
        Intrinsics.checkNotNullParameter(images, "images");
        Intrinsics.checkNotNullParameter(meteringData, "meteringData");
        cVar.b = diagramShapes;
        cVar.c = images;
        AssistantGradingSettings gradingSettings = new AssistantGradingSettings(z, z2);
        Intrinsics.checkNotNullParameter(meteringData, "<this>");
        LinkedHashMap meteringData2 = new LinkedHashMap();
        for (Map.Entry entry : meteringData.entrySet()) {
            P p2 = (P) entry.getKey();
            InterfaceC4176w0 interfaceC4176w02 = (InterfaceC4176w0) entry.getValue();
            if (interfaceC4176w02 instanceof C4179x0) {
                com.quizlet.shared.enums.h hVarB = AbstractC3097a5.b(p2);
                C4179x0 c4179x0 = (C4179x0) interfaceC4176w02;
                Intrinsics.checkNotNullParameter(c4179x0, "<this>");
                meteringData2.put(hVarB, new MeteredEvent(c4179x0.a, c4179x0.b));
            }
        }
        Intrinsics.checkNotNullParameter(studiableData, "studiableData");
        Intrinsics.checkNotNullParameter(gradingSettings, "gradingSettings");
        Intrinsics.checkNotNullParameter(meteringData2, "meteringData");
        Intrinsics.checkNotNullParameter(studiableData, "studiableData");
        Intrinsics.checkNotNullParameter(gradingSettings, "gradingSettings");
        Intrinsics.checkNotNullParameter(meteringData2, "meteringData");
        C1608n c1608n = new C1608n();
        c1608n.a = gradingSettings;
        H2.e(null);
        AbstractC3398u2.b(assistantMode.di.c.a);
        c1608n.c = assistantMode.refactored.shims.b.b(studiableData, false, null);
        com.quizlet.quizletandroid.ui.activitycenter.views.i meteringDataStore = new com.quizlet.quizletandroid.ui.activitycenter.views.i(meteringData2);
        Intrinsics.checkNotNullParameter(meteringDataStore, "meteringDataStore");
        c1608n.e = new metering.manager.a(meteringDataStore);
        cVar.a = c1608n;
        this.H = true;
        return cVar;
    }

    public final boolean D() {
        Object objA = this.c.a("selectedOnlyIntent");
        if (objA != null) {
            return ((Boolean) objA).booleanValue();
        }
        throw new IllegalArgumentException("Required value was null.");
    }

    public final QuestionSettings E() {
        return QuestionSettings.a(this.D.g().c(), null, null, false, false, false, false, false, false, false, null, null, false, false, false, false, false, 262139);
    }

    public final void F() {
        long j = this.D.u;
        com.quizlet.quizletandroid.ui.studymodes.testmode.logging.a aVar = this.o;
        aVar.getClass();
        TestEventLog.Companion companion = TestEventLog.b;
        com.quizlet.features.infra.basestudy.data.models.logging.a[] aVarArr = com.quizlet.features.infra.basestudy.data.models.logging.a.a;
        String setId = String.valueOf(j);
        companion.getClass();
        Intrinsics.checkNotNullParameter("study_mode_back_button_clicked", "actionName");
        Intrinsics.checkNotNullParameter(setId, "setId");
        TestEventLog testEventLog = new TestEventLog(null, 1, null);
        testEventLog.setAction("study_mode_back_button_clicked");
        testEventLog.setPayload(new TestPayload.Click(setId));
        aVar.a.l(testEventLog);
        this.h.b(true);
        if (this.G) {
            this.w.j(com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.b);
        } else {
            this.u.j(Boolean.valueOf(this.s.d() instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.r));
        }
    }

    public final void G(StudiableMeteringData meteringData, boolean z) {
        StudiableMeteringData studiableMeteringDataD;
        Intrinsics.checkNotNullParameter(meteringData, "meteringData");
        boolean z2 = meteringData.a == com.quizlet.shared.enums.h.d;
        if (z2) {
            I(meteringData);
        }
        if (z2) {
            InterfaceC4176w0 interfaceC4176w0 = this.I;
            if (interfaceC4176w0 == null) {
                Intrinsics.m("testMeteredEvent");
                throw null;
            }
            studiableMeteringDataD = AbstractC3097a5.d(interfaceC4176w0);
        } else {
            InterfaceC4176w0 interfaceC4176w02 = this.J;
            if (interfaceC4176w02 == null) {
                Intrinsics.m("learnMeteredEvent");
                throw null;
            }
            studiableMeteringDataD = AbstractC3097a5.d(interfaceC4176w02);
        }
        StudiableMeteringData studiableMeteringData = studiableMeteringDataD;
        Y y = this.s;
        com.quizlet.features.infra.basestudy.manager.f fVar = this.D;
        y.j(new com.quizlet.quizletandroid.ui.studymodes.testmode.models.k(fVar.u, fVar.t, studiableMeteringData, z));
    }

    public final void I(StudiableMeteringData studiableMeteringData) {
        Integer num;
        if (studiableMeteringData == null || (num = studiableMeteringData.c) == null) {
            return;
        }
        io.reactivex.rxjava3.internal.observers.e eVarI = this.l.q().i(new C(this, studiableMeteringData.d, num.intValue()), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        Intrinsics.checkNotNullParameter(eVarI, "<this>");
        A(eVarI);
    }

    public final void J(int i) {
        this.B = i;
        this.d.d = i;
        io.reactivex.rxjava3.disposables.b bVarU = this.D.c().u(new com.quizlet.billing.manager.b(24, this, (StudiableQuestion) this.e.a.get(i)), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
        Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
        Intrinsics.checkNotNullParameter(bVarU, "<this>");
        A(bVarU);
    }
}
