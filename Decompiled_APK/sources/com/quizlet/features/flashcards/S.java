package com.quizlet.features.flashcards;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import assistantMode.enums.EnumC1448b;
import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import assistantMode.refactored.types.flashcards.FlashcardsSubmitAction;
import assistantMode.refactored.types.flashcards.FlashcardsUndoAction;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.google.android.gms.internal.mlkit_vision_barcode.E6;
import com.quizlet.eventlogger.features.autolaunch.AutoLaunchEventLogger;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.studiablemodels.StudiableAudio;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.collections.C4927s;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

@Metadata
/* loaded from: classes2.dex */
public final class S extends com.quizlet.viewmodel.b {
    public boolean A;
    public y0 B;
    public y0 C;
    public y0 D;
    public Long E;
    public final com.quizlet.features.flashcards.engine.h c;
    public final com.quizlet.quizletandroid.managers.audio.h d;
    public final androidx.work.impl.model.v e;
    public final com.quizlet.features.infra.basestudy.usecase.b f;
    public final com.quizlet.data.interactor.set.c g;
    public final com.quizlet.features.flashcards.logging.a h;
    public final androidx.work.impl.model.c i;
    public final AutoLaunchEventLogger j;
    public final com.quizlet.time.b k;
    public final StudyableModelData l;
    public final long m;
    public final long n;
    public final int o;
    public final boolean p;
    public final String q;
    public final d0 r;
    public final X s;
    public final Y t;
    public final s0 u;
    public final d0 v;
    public final com.quizlet.features.infra.basestudy.manager.f w;
    public boolean x;
    public boolean y;
    public int z;

    public S(m0 savedStateHandle, com.quizlet.features.infra.basestudy.manager.a studyModeManagerFactory, com.quizlet.features.flashcards.engine.h flashcardsEngineManager, com.quizlet.quizletandroid.managers.audio.h audioManager, androidx.work.impl.model.v flashcardsPreferencesManager, com.quizlet.features.infra.basestudy.usecase.b getLearnNavigationUseCase, com.quizlet.data.interactor.set.c getTestMeteringDataUseCase, com.quizlet.features.flashcards.logging.a flashcardsEventLogger, androidx.work.impl.model.c userProperties, AutoLaunchEventLogger autoLaunchEventLogger) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(studyModeManagerFactory, "studyModeManagerFactory");
        Intrinsics.checkNotNullParameter(flashcardsEngineManager, "flashcardsEngineManager");
        Intrinsics.checkNotNullParameter(audioManager, "audioManager");
        Intrinsics.checkNotNullParameter(flashcardsPreferencesManager, "flashcardsPreferencesManager");
        Intrinsics.checkNotNullParameter(getLearnNavigationUseCase, "getLearnNavigationUseCase");
        Intrinsics.checkNotNullParameter(getTestMeteringDataUseCase, "getTestMeteringDataUseCase");
        Intrinsics.checkNotNullParameter(flashcardsEventLogger, "flashcardsEventLogger");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(autoLaunchEventLogger, "autoLaunchEventLogger");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.c = flashcardsEngineManager;
        this.d = audioManager;
        this.e = flashcardsPreferencesManager;
        this.f = getLearnNavigationUseCase;
        this.g = getTestMeteringDataUseCase;
        this.h = flashcardsEventLogger;
        this.i = userProperties;
        this.j = autoLaunchEventLogger;
        this.k = timeProvider;
        Object objA = savedStateHandle.a("studyableModelData");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        StudyableModelData studyableModelData = (StudyableModelData) objA;
        this.l = studyableModelData;
        this.m = studyableModelData.k();
        Object objA2 = savedStateHandle.a("studyableModelLocalId");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.n = ((Number) objA2).longValue();
        Object objA3 = savedStateHandle.a("navigationSource");
        if (objA3 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.o = ((Number) objA3).intValue();
        Object objA4 = savedStateHandle.a("selectedOnlyIntent");
        if (objA4 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.p = ((Boolean) objA4).booleanValue();
        Object objA5 = savedStateHandle.a("studyableModelTitle");
        if (objA5 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.q = (String) objA5;
        this.r = e0.b(0, 1, null, 5);
        this.s = new X(1);
        new X(1);
        com.quizlet.features.flashcards.data.p pVar = com.quizlet.features.flashcards.data.p.a;
        Y y = new Y(pVar);
        this.t = y;
        this.u = e0.c(com.quizlet.features.flashcards.autoplay.f.a);
        new X(1);
        this.v = e0.b(0, 1, null, 5);
        com.quizlet.features.infra.basestudy.manager.f fVarA = studyModeManagerFactory.a(savedStateHandle);
        this.w = fVarA;
        this.z = 1;
        com.quizlet.features.infra.basestudy.manager.f.h(fVarA);
        y.l(pVar);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new P(this, null), 3);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new M(this, null), 3);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new y(this, null), 3);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object B(com.quizlet.features.flashcards.S r5, java.lang.String r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5.getClass()
            boolean r0 = r7 instanceof com.quizlet.features.flashcards.w
            if (r0 == 0) goto L16
            r0 = r7
            com.quizlet.features.flashcards.w r0 = (com.quizlet.features.flashcards.w) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.features.flashcards.w r0 = new com.quizlet.features.flashcards.w
            r0.<init>(r5, r7)
        L1b:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            com.quizlet.features.flashcards.data.a r3 = com.quizlet.features.flashcards.data.a.a
            r4 = 1
            if (r2 == 0) goto L3a
            if (r2 != r4) goto L32
            com.quizlet.features.flashcards.S r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.io.IOException -> L2e java.lang.IllegalStateException -> L30
            goto L63
        L2e:
            r6 = move-exception
            goto L4e
        L30:
            r6 = move-exception
            goto L59
        L32:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.quizletandroid.managers.audio.h r7 = r5.d     // Catch: java.io.IOException -> L2e java.lang.IllegalStateException -> L30
            io.reactivex.rxjava3.internal.operators.completable.a r6 = r7.a(r6)     // Catch: java.io.IOException -> L2e java.lang.IllegalStateException -> L30
            r0.j = r5     // Catch: java.io.IOException -> L2e java.lang.IllegalStateException -> L30
            r0.m = r4     // Catch: java.io.IOException -> L2e java.lang.IllegalStateException -> L30
            java.lang.Object r5 = com.google.android.gms.internal.mlkit_vision_camera.I1.a(r6, r0)     // Catch: java.io.IOException -> L2e java.lang.IllegalStateException -> L30
            if (r5 != r1) goto L63
            return r1
        L4e:
            timber.log.a r7 = timber.log.c.a
            r7.e(r6)
            androidx.lifecycle.X r5 = r5.s
            r5.j(r3)
            goto L63
        L59:
            timber.log.a r7 = timber.log.c.a
            r7.e(r6)
            androidx.lifecycle.X r5 = r5.s
            r5.j(r3)
        L63:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.S.B(com.quizlet.features.flashcards.S, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final String C(S s) {
        Object objD = s.t.d();
        com.quizlet.features.flashcards.data.q qVar = objD instanceof com.quizlet.features.flashcards.data.q ? (com.quizlet.features.flashcards.data.q) objD : null;
        Integer numValueOf = qVar != null ? Integer.valueOf(qVar.b) : null;
        return (numValueOf != null && numValueOf.intValue() == 0) ? "results" : "checkpoint";
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object D(com.quizlet.features.flashcards.S r10, kotlin.coroutines.jvm.internal.c r11) {
        /*
            r10.getClass()
            boolean r0 = r11 instanceof com.quizlet.features.flashcards.z
            if (r0 == 0) goto L17
            r0 = r11
            com.quizlet.features.flashcards.z r0 = (com.quizlet.features.flashcards.z) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L17
            int r1 = r1 - r2
            r0.m = r1
        L15:
            r6 = r0
            goto L1d
        L17:
            com.quizlet.features.flashcards.z r0 = new com.quizlet.features.flashcards.z
            r0.<init>(r10, r11)
            goto L15
        L1d:
            java.lang.Object r11 = r6.k
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.m
            r2 = 1
            if (r1 == 0) goto L36
            if (r1 != r2) goto L2e
            com.quizlet.features.flashcards.S r10 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L4b
        L2e:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            r6.j = r10
            r6.m = r2
            r5 = 0
            com.quizlet.features.infra.basestudy.usecase.b r1 = r10.f
            com.quizlet.features.infra.models.studymodeshared.StudyableModelData r2 = r10.l
            long r3 = r10.n
            java.lang.Object r11 = r1.a(r2, r3, r5, r6)
            if (r11 != r0) goto L4b
            return r0
        L4b:
            com.quizlet.features.infra.basestudy.usecase.e r11 = (com.quizlet.features.infra.basestudy.usecase.e) r11
            kotlinx.coroutines.flow.d0 r0 = r10.r
            com.quizlet.data.model.w0 r8 = r11.a
            com.quizlet.features.flashcards.data.g r1 = new com.quizlet.features.flashcards.data.g
            long r4 = r10.n
            java.lang.String r6 = r10.q
            int r2 = r10.o
            com.quizlet.features.infra.models.studymodeshared.StudyableModelData r3 = r10.l
            boolean r7 = r10.p
            boolean r9 = r11.b
            r1.<init>(r2, r3, r4, r6, r7, r8, r9)
            r0.h(r1)
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.S.D(com.quizlet.features.flashcards.S, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object E(com.quizlet.features.flashcards.S r10, kotlin.coroutines.jvm.internal.c r11) {
        /*
            r10.getClass()
            boolean r0 = r11 instanceof com.quizlet.features.flashcards.A
            if (r0 == 0) goto L17
            r0 = r11
            com.quizlet.features.flashcards.A r0 = (com.quizlet.features.flashcards.A) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L17
            int r1 = r1 - r2
            r0.n = r1
        L15:
            r6 = r0
            goto L1d
        L17:
            com.quizlet.features.flashcards.A r0 = new com.quizlet.features.flashcards.A
            r0.<init>(r10, r11)
            goto L15
        L1d:
            java.lang.Object r11 = r6.l
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.n
            r7 = 2
            r2 = 1
            if (r1 == 0) goto L42
            if (r1 == r2) goto L3c
            if (r1 != r7) goto L34
            com.quizlet.data.model.w0 r10 = r6.k
            com.quizlet.features.flashcards.S r0 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            r8 = r10
            goto L6f
        L34:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L3c:
            com.quizlet.features.flashcards.S r10 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L57
        L42:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            r6.j = r10
            r6.n = r2
            r5 = 0
            com.quizlet.features.infra.basestudy.usecase.b r1 = r10.f
            com.quizlet.features.infra.models.studymodeshared.StudyableModelData r2 = r10.l
            long r3 = r10.n
            java.lang.Object r11 = r1.a(r2, r3, r5, r6)
            if (r11 != r0) goto L57
            goto L6b
        L57:
            com.quizlet.features.infra.basestudy.usecase.e r11 = (com.quizlet.features.infra.basestudy.usecase.e) r11
            com.quizlet.data.model.w0 r11 = r11.a
            com.quizlet.data.interactor.set.c r1 = r10.g
            r6.j = r10
            r6.k = r11
            r6.n = r7
            long r2 = r10.m
            java.lang.Object r1 = r1.o(r2, r6)
            if (r1 != r0) goto L6c
        L6b:
            return r0
        L6c:
            r0 = r10
            r8 = r11
            r11 = r1
        L6f:
            r9 = r11
            com.quizlet.data.model.w0 r9 = (com.quizlet.data.model.InterfaceC4176w0) r9
            kotlinx.coroutines.flow.d0 r10 = r0.r
            com.quizlet.features.flashcards.data.k r2 = new com.quizlet.features.flashcards.data.k
            long r5 = r0.n
            boolean r7 = r0.p
            int r3 = r0.o
            com.quizlet.features.infra.models.studymodeshared.StudyableModelData r4 = r0.l
            r2.<init>(r3, r4, r5, r7, r8, r9)
            r10.h(r2)
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.S.E(com.quizlet.features.flashcards.S, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void F() {
        com.quizlet.features.infra.models.flashcards.k kVar;
        com.quizlet.features.infra.models.flashcards.j jVar;
        if (G().j == null) {
            return;
        }
        this.t.l(com.quizlet.features.flashcards.data.o.a(G(), 0, 0, 0, 0, false, false, false, false, null, null, 959));
        if (this.y) {
            return;
        }
        com.quizlet.features.infra.models.flashcards.d dVarD = this.c.d();
        String str = dVarD.a.a;
        String str2 = dVarD.b.a;
        boolean z = dVarD.c;
        boolean z2 = dVarD.d;
        if (z || z2) {
            StudiableAudio studiableAudio = null;
            com.quizlet.features.flashcards.data.b bVar = G().j;
            if (bVar != null) {
                int iOrdinal = bVar.g.ordinal();
                if (iOrdinal == 0) {
                    D6 d6 = bVar.c;
                    if (d6 instanceof com.quizlet.features.infra.models.flashcards.j) {
                        jVar = (com.quizlet.features.infra.models.flashcards.j) d6;
                        studiableAudio = jVar.c;
                    } else if (d6 instanceof com.quizlet.features.infra.models.flashcards.k) {
                        kVar = (com.quizlet.features.infra.models.flashcards.k) d6;
                        studiableAudio = kVar.b;
                    }
                } else {
                    if (iOrdinal != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    D6 d62 = bVar.d;
                    if (d62 instanceof com.quizlet.features.infra.models.flashcards.j) {
                        jVar = (com.quizlet.features.infra.models.flashcards.j) d62;
                        studiableAudio = jVar.c;
                    } else if (d62 instanceof com.quizlet.features.infra.models.flashcards.k) {
                        kVar = (com.quizlet.features.infra.models.flashcards.k) d62;
                        studiableAudio = kVar.b;
                    }
                }
            }
            if (G().f || studiableAudio == null) {
                return;
            }
            N(studiableAudio);
        }
    }

    public final com.quizlet.features.flashcards.data.o G() {
        Object objD = this.t.d();
        com.quizlet.features.flashcards.data.o oVar = objD instanceof com.quizlet.features.flashcards.data.o ? (com.quizlet.features.flashcards.data.o) objD : null;
        if (oVar != null) {
            return oVar;
        }
        com.quizlet.features.flashcards.data.m mVar = com.quizlet.features.flashcards.data.m.e;
        if ((1023 & 256) != 0) {
            mVar = null;
        }
        return new com.quizlet.features.flashcards.data.o(0, 0, 0, 0, false, false, false, false, mVar, null);
    }

    public final void H() {
        y0 y0Var = this.B;
        if (y0Var != null) {
            y0Var.j(null);
        }
        if (G().j == null) {
            return;
        }
        boolean z = this.x;
        Y y = this.t;
        if (z) {
            y.l(com.quizlet.features.flashcards.data.o.a(G(), 0, 0, 0, 0, false, false, false, false, null, null, 767));
        }
        if (this.A) {
            P();
            return;
        }
        switch (this.z) {
            case 1:
                y.l(com.quizlet.features.flashcards.data.o.a(G(), 0, 0, 0, 0, false, false, false, false, com.quizlet.features.flashcards.data.m.a, null, 767));
                break;
            case 2:
                y.l(com.quizlet.features.flashcards.data.o.a(G(), 0, 0, 0, 0, false, false, false, false, com.quizlet.features.flashcards.data.m.e, null, 767));
                break;
            case 3:
            case 4:
            case 5:
                y.l(com.quizlet.features.flashcards.data.o.a(G(), 0, 0, 0, 0, false, false, false, false, com.quizlet.features.flashcards.data.m.f, null, 767));
                break;
            case 6:
                kotlinx.coroutines.E.A(p0.j(this), null, null, new K(this, null), 3);
                break;
        }
    }

    public final void I() {
        boolean z;
        Object value;
        com.quizlet.features.flashcards.data.b bVar;
        Object value2;
        com.quizlet.features.flashcards.engine.h hVar = this.c;
        boolean z2 = hVar.d().e;
        boolean z3 = !z2;
        if (G().j != null) {
            z = z3;
            this.t.l(com.quizlet.features.flashcards.data.o.a(G(), 0, 0, 0, 0, false, z, false, false, null, null, 991));
            com.quizlet.features.flashcards.data.m mVar = !z2 ? com.quizlet.features.flashcards.data.m.g : com.quizlet.features.flashcards.data.m.h;
            y0 y0Var = this.B;
            if (y0Var != null) {
                y0Var.j(null);
            }
            this.B = kotlinx.coroutines.E.A(p0.j(this), com.facebook.appevents.iap.u.d(), null, new L(this, mVar, null), 2);
        } else {
            z = z3;
        }
        com.quizlet.features.flashcards.logging.a aVar = hVar.d;
        com.quizlet.features.flashcards.logging.a.a(aVar, "toggle_flashcards_auto_play", null, null, Boolean.valueOf(z), 54);
        if (!z2) {
            com.quizlet.features.flashcards.logging.a.a(aVar, "start_play", null, null, null, 62);
        }
        hVar.p(com.quizlet.features.infra.models.flashcards.d.a(hVar.d(), null, null, z, false, 0L, 0, 495));
        com.quizlet.features.flashcards.data.o oVarG = G();
        s0 s0Var = this.u;
        if (z2 || (bVar = oVarG.j) == null) {
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, com.quizlet.features.flashcards.autoplay.f.a));
        } else {
            boolean z4 = hVar.d().c;
            do {
                value2 = s0Var.getValue();
            } while (!s0Var.k(value2, new com.quizlet.features.flashcards.autoplay.q(bVar, z4, hVar)));
        }
    }

    public final void J() {
        boolean zB = Intrinsics.b(this.t.d(), com.quizlet.features.flashcards.data.p.a);
        com.quizlet.features.flashcards.engine.h hVar = this.c;
        if (!zB && hVar.d().e) {
            I();
        }
        this.r.h(new com.quizlet.features.flashcards.data.f(hVar.h));
    }

    public final void K(boolean z) {
        s0 s0Var;
        Object value;
        com.quizlet.features.flashcards.data.o oVarG = G();
        com.quizlet.features.flashcards.engine.h hVar = this.c;
        com.quizlet.features.flashcards.data.b bVar = oVarG.j;
        if (bVar != null) {
            com.quizlet.features.infra.models.flashcards.h hVar2 = bVar.g;
            hVar2.getClass();
            com.quizlet.features.infra.models.flashcards.h hVar3 = com.quizlet.features.infra.models.flashcards.h.a;
            if (hVar2 == hVar3) {
                hVar3 = com.quizlet.features.infra.models.flashcards.h.b;
            }
            com.quizlet.features.flashcards.data.b bVarB = com.quizlet.features.flashcards.data.b.b(bVar, false, hVar3, 95);
            if (z && G().f) {
                do {
                    s0Var = this.u;
                    value = s0Var.getValue();
                } while (!s0Var.k(value, new com.quizlet.features.flashcards.autoplay.q(bVarB, hVar.d().c, hVar)));
            }
            this.t.l(com.quizlet.features.flashcards.data.o.a(G(), 0, 0, 0, 0, false, false, false, false, null, bVarB, 511));
        }
        com.quizlet.features.flashcards.data.b bVar2 = G().j;
        com.quizlet.features.infra.models.flashcards.h hVar4 = bVar2 != null ? bVar2.g : null;
        com.quizlet.features.flashcards.data.e eVar = hVar.i;
        Object obj = eVar != null ? eVar.a : null;
        com.quizlet.features.flashcards.data.b bVar3 = obj instanceof com.quizlet.features.flashcards.data.b ? (com.quizlet.features.flashcards.data.b) obj : null;
        if (bVar3 != null) {
            String studySessionId = hVar.n.t;
            if (hVar.q == null) {
                hVar.q = UUID.randomUUID().toString();
            }
            String questionSessionId = hVar.q;
            Intrinsics.d(questionSessionId);
            com.quizlet.features.flashcards.logging.c questionLoggingData = com.quizlet.features.flashcards.engine.h.n(bVar3);
            assistantMode.enums.m frontSide = hVar.d().a;
            assistantMode.enums.m revealSide = E6.f(hVar4, hVar.d());
            com.quizlet.features.flashcards.logging.b bVar4 = hVar.f;
            Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
            Intrinsics.checkNotNullParameter(questionSessionId, "questionSessionId");
            Intrinsics.checkNotNullParameter(questionLoggingData, "questionLoggingData");
            Intrinsics.checkNotNullParameter(frontSide, "frontSide");
            Intrinsics.checkNotNullParameter(revealSide, "revealSide");
            bVar4.a.v(com.quizlet.features.flashcards.logging.b.a(studySessionId, questionSessionId, "reveal", questionLoggingData, frontSide, revealSide, null, null, null));
        }
        F();
        if (G().i == com.quizlet.features.flashcards.data.m.a) {
            P();
        }
    }

    public final void L(EnumC1448b enumC1448b) {
        if (G().f) {
            this.v.h(com.quizlet.ui.compose.L.a);
        }
        com.quizlet.features.flashcards.data.b bVar = G().j;
        if (bVar != null) {
            this.A = false;
            this.z++;
            H();
            if (!G().e) {
                enumC1448b = EnumC1448b.b;
            }
            this.c.l(enumC1448b, bVar.g);
        }
    }

    public final void M() {
        kotlinx.coroutines.E.A(p0.j(this), null, null, new D(this, null), 3);
    }

    public final void N(StudiableAudio audio) {
        s0 s0Var;
        Object value;
        Intrinsics.checkNotNullParameter(audio, "audio");
        do {
            s0Var = this.u;
            value = s0Var.getValue();
        } while (!s0Var.k(value, com.quizlet.features.flashcards.autoplay.p.a));
        kotlinx.coroutines.E.A(p0.j(this), null, null, new E(this, audio, null), 3);
    }

    public final void O() {
        int i;
        com.quizlet.features.flashcards.engine.h hVar = this.c;
        if (((assistantMode.refactored.studyEngines.b) hVar.b().c).m.isEmpty()) {
            return;
        }
        com.quizlet.features.flashcards.logging.a.a(hVar.d, "response_did_tap_undo", null, null, null, 62);
        com.quizlet.data.interactor.set.c cVarB = hVar.b();
        assistantMode.refactored.studyEngines.b bVar = (assistantMode.refactored.studyEngines.b) cVarB.c;
        C4927s c4927s = bVar.m;
        Pair pair = (Pair) (c4927s.isEmpty() ? null : c4927s.removeLast());
        if (pair == null) {
            throw new IllegalStateException("No actions available to undo");
        }
        com.quizlet.shared.enums.t tVar = (com.quizlet.shared.enums.t) pair.a;
        FlashcardsSubmitAction flashcardsSubmitAction = (FlashcardsSubmitAction) pair.b;
        RevealSelfAssessmentQuestion revealSelfAssessmentQuestionA = bVar.a();
        kotlin.collections.G.A(bVar.c);
        kotlin.collections.G.A(bVar.f);
        int iOrdinal = tVar.ordinal();
        if (iOrdinal == 0) {
            List list = bVar.e;
            if (list == null || !list.isEmpty()) {
                Iterator it2 = list.iterator();
                i = 0;
                while (it2.hasNext()) {
                    if (Intrinsics.b((RevealSelfAssessmentQuestion) it2.next(), flashcardsSubmitAction.a) && (i = i + 1) < 0) {
                        kotlin.collections.B.o();
                        throw null;
                    }
                }
            } else {
                i = 0;
            }
            if (i != 1) {
                throw new IllegalStateException("Cannot undo: expected exactly one instance of flashcard");
            }
            kotlin.collections.G.y(list, new androidx.credentials.playservices.controllers.BeginSignIn.c(flashcardsSubmitAction, 11));
        } else if (iOrdinal == 1) {
            bVar.q--;
        }
        bVar.d.add(0, flashcardsSubmitAction.a);
        ArrayList arrayList = bVar.n.a;
        Intrinsics.checkNotNullParameter(arrayList, "<this>");
        bVar.r = new FlashcardsUndoAction(revealSelfAssessmentQuestionA, flashcardsSubmitAction);
        hVar.g(hVar.o(((assistantMode.refactored.studyEngines.b) cVarB.c).b()));
    }

    public final void P() {
        this.A = true;
        y0 y0Var = this.B;
        if (y0Var != null) {
            y0Var.j(null);
        }
        if (G().e) {
            this.B = kotlinx.coroutines.E.A(p0.j(this), com.facebook.appevents.iap.u.d(), null, new O(this, null), 2);
        } else {
            this.t.l(com.quizlet.features.flashcards.data.o.a(G(), 0, 0, 0, 0, false, false, false, false, com.quizlet.features.flashcards.data.m.d, null, 767));
        }
    }

    @Override // com.quizlet.viewmodel.b, androidx.lifecycle.w0
    public final void z() {
        super.z();
        com.quizlet.features.flashcards.engine.h hVar = this.c;
        kotlinx.coroutines.E.A(kotlinx.coroutines.E.c(hVar.g), null, null, new com.quizlet.features.flashcards.engine.f(hVar, null), 3);
        com.quizlet.features.flashcards.data.b bVar = G().j;
        hVar.f(bVar != null ? bVar.g : null);
        y0 y0Var = this.C;
        if (y0Var != null) {
            y0Var.j(null);
        }
        this.C = null;
        y0 y0Var2 = this.D;
        if (y0Var2 != null) {
            y0Var2.j(null);
        }
        this.D = null;
    }
}
