package com.quizlet.quizletandroid.ui.studymodes.testmode.start;

import androidx.lifecycle.m0;
import androidx.lifecycle.w0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import com.quizlet.generated.enums.O1;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class A extends w0 implements InterfaceC4758b {
    public final m0 b;
    public final StudyModeEventLogger c;
    public final com.google.mlkit.vision.documentscanner.internal.c d;
    public final com.quizlet.data.interactor.achievements.f e;
    public final com.google.firebase.crashlytics.internal.settings.b f;
    public final com.quizlet.features.infra.basestudy.manager.f g;
    public final s0 h;
    public final d0 i;
    public int j;

    public A(m0 savedStateHandle, StudyModeEventLogger studyModeEventLogger, com.google.mlkit.vision.documentscanner.internal.c getTestScoreUseCase, com.quizlet.data.interactor.achievements.f settingsTermUseCase, com.google.firebase.crashlytics.internal.settings.b settingsDefinitionUseCase, com.quizlet.features.infra.basestudy.manager.a studyModeManagerFactory) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(studyModeEventLogger, "studyModeEventLogger");
        Intrinsics.checkNotNullParameter(getTestScoreUseCase, "getTestScoreUseCase");
        Intrinsics.checkNotNullParameter(settingsTermUseCase, "settingsTermUseCase");
        Intrinsics.checkNotNullParameter(settingsDefinitionUseCase, "settingsDefinitionUseCase");
        Intrinsics.checkNotNullParameter(studyModeManagerFactory, "studyModeManagerFactory");
        this.b = savedStateHandle;
        this.c = studyModeEventLogger;
        this.d = getTestScoreUseCase;
        this.e = settingsTermUseCase;
        this.f = settingsDefinitionUseCase;
        this.g = studyModeManagerFactory.a(savedStateHandle);
        this.h = e0.c(d.a);
        this.i = e0.b(0, 0, null, 7);
        this.j = 20;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.quizletandroid.ui.studymodes.testmode.start.A r26, com.quizlet.quizletandroid.ui.studymodes.testmode.start.i r27, kotlin.coroutines.jvm.internal.c r28) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 445
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.testmode.start.A.A(com.quizlet.quizletandroid.ui.studymodes.testmode.start.A, com.quizlet.quizletandroid.ui.studymodes.testmode.start.i, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static j D(List list, O1 o1, Function1 function1) {
        return new j(function1, list.contains(o1));
    }

    public final InterfaceC4176w0 B() {
        InterfaceC4176w0 interfaceC4176w0 = (InterfaceC4176w0) this.b.a("arg_metered_event");
        if (interfaceC4176w0 != null) {
            return interfaceC4176w0;
        }
        throw new IllegalStateException("Required argument not present: (arg_metered_event)");
    }

    public final StudyEventLogData C() {
        StudyEventLogData studyEventLogData = (StudyEventLogData) this.b.a("arg_study_event_log_data");
        if (studyEventLogData != null) {
            return studyEventLogData;
        }
        throw new IllegalStateException("Required argument not present: (arg_study_event_log_data)");
    }

    public final void E(O1 o1, boolean z) {
        Object value = this.h.getValue();
        c cVar = value instanceof c ? (c) value : null;
        if (cVar == null) {
            return;
        }
        int i = v.a[o1.ordinal()];
        C4757a c4757aA = cVar.l;
        if (i == 1) {
            c4757aA = C4757a.a(c4757aA, j.a(c4757aA.a, z), null, null, null, null, null, 254);
        } else if (i == 2) {
            c4757aA = C4757a.a(c4757aA, null, j.a(c4757aA.b, z), null, null, null, null, 253);
        } else if (i == 3) {
            c4757aA = C4757a.a(c4757aA, null, null, new j(new u(this, 7), z), null, null, null, 251);
        }
        G(c.a(cVar, null, null, null, null, null, false, c4757aA, 2047));
    }

    public final void F(O1 o1, boolean z) {
        Object value = this.h.getValue();
        c cVar = value instanceof c ? (c) value : null;
        if (cVar == null) {
            return;
        }
        int i = v.a[o1.ordinal()];
        C4757a c4757aA = cVar.l;
        if (i == 1) {
            c4757aA = C4757a.a(c4757aA, null, null, null, j.a(c4757aA.d, z), null, null, 247);
        } else if (i == 2) {
            c4757aA = C4757a.a(c4757aA, null, null, null, null, j.a(c4757aA.e, z), null, 239);
        } else if (i == 3) {
            c4757aA = C4757a.a(c4757aA, null, null, null, null, null, new j(new u(this, 6), z), 223);
        }
        G(c.a(cVar, null, null, null, null, null, false, c4757aA, 2047));
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x004c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void G(com.quizlet.quizletandroid.ui.studymodes.testmode.start.c r14) {
        /*
            r13 = this;
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.j r0 = r14.g
            boolean r0 = r0.a
            r1 = 0
            if (r0 != 0) goto L13
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.j r0 = r14.h
            boolean r0 = r0.a
            if (r0 != 0) goto L13
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.j r0 = r14.f
            boolean r0 = r0.a
            if (r0 == 0) goto L4c
        L13:
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.a r0 = r14.l
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.j r2 = r0.a
            boolean r2 = r2.a
            r3 = 1
            if (r2 != 0) goto L2d
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.j r2 = r0.b
            boolean r2 = r2.a
            if (r2 != 0) goto L2d
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.j r2 = r0.c
            if (r2 == 0) goto L2b
            boolean r2 = r2.a
            if (r2 != r3) goto L2b
            goto L2d
        L2b:
            r2 = r1
            goto L2e
        L2d:
            r2 = r3
        L2e:
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.j r4 = r0.d
            boolean r4 = r4.a
            if (r4 != 0) goto L45
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.j r4 = r0.e
            boolean r4 = r4.a
            if (r4 != 0) goto L45
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.j r0 = r0.f
            if (r0 == 0) goto L43
            boolean r0 = r0.a
            if (r0 != r3) goto L43
            goto L45
        L43:
            r0 = r1
            goto L46
        L45:
            r0 = r3
        L46:
            if (r2 == 0) goto L4c
            if (r0 == 0) goto L4c
            r10 = r3
            goto L4d
        L4c:
            r10 = r1
        L4d:
            kotlinx.coroutines.flow.s0 r0 = r13.h
            java.lang.Object r1 = r0.getValue()
            r2 = r1
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.B r2 = (com.quizlet.quizletandroid.ui.studymodes.testmode.start.B) r2
            r9 = 0
            r11 = 0
            r5 = 0
            r6 = 0
            r7 = 0
            r8 = 0
            r12 = 3583(0xdff, float:5.021E-42)
            r4 = r14
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.c r14 = com.quizlet.quizletandroid.ui.studymodes.testmode.start.c.a(r4, r5, r6, r7, r8, r9, r10, r11, r12)
            boolean r14 = r0.k(r1, r14)
            if (r14 == 0) goto L6a
            return
        L6a:
            r14 = r4
            goto L4d
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.testmode.start.A.G(com.quizlet.quizletandroid.ui.studymodes.testmode.start.c):void");
    }
}
