package com.quizlet.explanations.myexplanations.viewmodel;

import androidx.camera.camera2.internal.c0;
import androidx.lifecycle.C1247h;
import androidx.lifecycle.C1249j;
import androidx.lifecycle.C1259u;
import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.navigation.U;
import com.google.android.gms.internal.mlkit_vision_barcode.C6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import kotlin.Metadata;
import kotlin.collections.B;
import kotlin.collections.C4933y;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.A0;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.E;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.O;
import kotlinx.coroutines.flow.C4986c;
import kotlinx.coroutines.flow.q0;

@Metadata
/* loaded from: classes2.dex */
public final class m extends com.quizlet.viewmodel.a implements a {
    public final com.quizlet.data.repository.explanations.myexplanations.a d;
    public final ExplanationsLogger e;
    public final androidx.work.impl.model.c f;
    public final com.quizlet.explanations.myexplanations.ui.viewpager.a g;
    public final String h;
    public final int i;
    public final Y j;
    public final X k;
    public final Y l;
    public final X m;
    public final Y n;
    public final X o;
    public final X p;
    public final X q;

    /* JADX WARN: Multi-variable type inference failed */
    public m(m0 savedStateHandle, com.quizlet.data.repository.explanations.myexplanations.a getMyExplanationsUseCase, ExplanationsLogger explanationsLogger, androidx.work.impl.model.c userProperties) {
        int i = 17;
        int i2 = 1;
        int i3 = 0;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(getMyExplanationsUseCase, "getMyExplanationsUseCase");
        Intrinsics.checkNotNullParameter(explanationsLogger, "explanationsLogger");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        this.d = getMyExplanationsUseCase;
        this.e = explanationsLogger;
        this.f = userProperties;
        io.reactivex.rxjava3.core.i iVarM = userProperties.t().m();
        Intrinsics.checkNotNullExpressionValue(iVarM, "toObservable(...)");
        C4986c c4986cF = K1.f(iVarM);
        androidx.lifecycle.viewmodel.internal.a aVarJ = p0.j(this);
        Intrinsics.checkNotNullParameter(c4986cF, "<this>");
        CoroutineContext context = aVarJ.a;
        Intrinsics.checkNotNullParameter(context, "context");
        C1259u block = new C1259u(c4986cF, null);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(block, "block");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(block, "block");
        C1249j c1249j = new C1249j(0);
        A0 a0 = new A0((InterfaceC5025j0) context.get(C5023i0.a));
        kotlinx.coroutines.scheduling.e eVar = O.a;
        c1249j.n = new c0(c1249j, block, E.c(kotlinx.coroutines.internal.m.a.e.plus(context).plus(a0)), new C1247h(c1249j, i3));
        if (c4986cF instanceof q0) {
            if (androidx.arch.core.executor.b.p().a.q()) {
                c1249j.l(((q0) c4986cF).getValue());
            } else {
                c1249j.j(((q0) c4986cF).getValue());
            }
        }
        com.quizlet.explanations.myexplanations.ui.viewpager.a aVar = (com.quizlet.explanations.myexplanations.ui.viewpager.a) savedStateHandle.a("startingPage");
        this.g = aVar == null ? com.quizlet.explanations.myexplanations.ui.viewpager.a.a : aVar;
        String str = (String) savedStateHandle.a("screenName");
        this.h = str == null ? "" : str;
        this.i = 20;
        com.quizlet.explanations.myexplanations.data.k kVar = com.quizlet.explanations.myexplanations.data.k.a;
        Y y = new Y(kVar);
        this.j = y;
        X xK = p0.k(y, new U(this, i));
        this.k = xK;
        Y y2 = new Y(kVar);
        this.l = y2;
        X xK2 = p0.k(y2, new U(this, i));
        this.m = xK2;
        Y y3 = new Y(kVar);
        this.n = y3;
        X xK3 = p0.k(y3, new U(this, i));
        this.o = xK3;
        C6.a(B.j(y2, y3), new l(this, i3));
        this.p = C6.a(B.j(xK, xK2, xK3), new l(this, i2));
        this.q = new X(1);
        E.A(p0.j(this), null, null, new i(this, null), 3);
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x009b  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00bc A[LOOP:1: B:30:0x00b6->B:32:0x00bc, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0104  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0109  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x010f  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object B(com.quizlet.explanations.myexplanations.viewmodel.m r24, kotlinx.coroutines.I r25, kotlin.coroutines.jvm.internal.c r26) {
        /*
            Method dump skipped, instructions count: 278
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.explanations.myexplanations.viewmodel.m.B(com.quizlet.explanations.myexplanations.viewmodel.m, kotlinx.coroutines.I, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00b1 A[LOOP:1: B:30:0x00ab->B:32:0x00b1, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00f0  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00f6  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object C(com.quizlet.explanations.myexplanations.viewmodel.m r13, kotlinx.coroutines.I r14, kotlin.coroutines.jvm.internal.c r15) {
        /*
            Method dump skipped, instructions count: 253
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.explanations.myexplanations.viewmodel.m.C(com.quizlet.explanations.myexplanations.viewmodel.m, kotlinx.coroutines.I, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x009b  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00b6  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00da A[LOOP:2: B:36:0x00d4->B:38:0x00da, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0112  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0117  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x011d  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object D(com.quizlet.explanations.myexplanations.viewmodel.m r19, kotlinx.coroutines.I r20, kotlin.coroutines.jvm.internal.c r21) {
        /*
            Method dump skipped, instructions count: 292
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.explanations.myexplanations.viewmodel.m.D(com.quizlet.explanations.myexplanations.viewmodel.m, kotlinx.coroutines.I, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static void G(Y y, com.quizlet.explanations.myexplanations.data.h hVar, kotlinx.collections.immutable.b bVar, int i, boolean z) {
        Object iVar;
        if (bVar.isEmpty()) {
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            iVar = new com.quizlet.explanations.myexplanations.data.i(new com.quizlet.qutils.string.f(i, C4933y.P(args)), z);
        } else {
            iVar = new com.quizlet.explanations.myexplanations.data.j(AbstractC3409x1.h(hVar), bVar);
        }
        y.j(iVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable E(java.util.List r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof com.quizlet.explanations.myexplanations.viewmodel.c
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.explanations.myexplanations.viewmodel.c r0 = (com.quizlet.explanations.myexplanations.viewmodel.c) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.explanations.myexplanations.viewmodel.c r0 = new com.quizlet.explanations.myexplanations.viewmodel.c
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            r4 = 0
            if (r2 == 0) goto L30
            if (r2 != r3) goto L28
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.Exception -> L47
            goto L44
        L28:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L30:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.data.repository.explanations.myexplanations.a r7 = r5.d     // Catch: java.lang.Exception -> L47
            io.reactivex.rxjava3.subjects.r r2 = r5.c     // Catch: java.lang.Exception -> L47
            io.reactivex.rxjava3.internal.operators.single.g r6 = r7.g(r4, r6, r2)     // Catch: java.lang.Exception -> L47
            r0.l = r3     // Catch: java.lang.Exception -> L47
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r6, r0)     // Catch: java.lang.Exception -> L47
            if (r7 != r1) goto L44
            return r1
        L44:
            java.util.List r7 = (java.util.List) r7     // Catch: java.lang.Exception -> L47
            goto L51
        L47:
            java.lang.Integer r4 = new java.lang.Integer
            r6 = 2132017501(0x7f14015d, float:1.9673282E38)
            r4.<init>(r6)
            kotlin.collections.K r7 = kotlin.collections.K.a
        L51:
            kotlin.Pair r6 = new kotlin.Pair
            r6.<init>(r7, r4)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.explanations.myexplanations.viewmodel.m.E(java.util.List, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public final void F(ExplanationsLogger.EventData eventData) {
        boolean z = this.p.d() instanceof com.quizlet.explanations.myexplanations.data.b;
        String screenName = this.h;
        ExplanationsLogger explanationsLogger = this.e;
        if (z) {
            explanationsLogger.getClass();
            Intrinsics.checkNotNullParameter(screenName, "screenName");
            Intrinsics.checkNotNullParameter(eventData, "eventData");
            ExplanationsEventLog.Companion companion = ExplanationsEventLog.b;
            com.quizlet.eventlogger.features.explanations.a aVar = new com.quizlet.eventlogger.features.explanations.a(2, eventData, explanationsLogger, screenName);
            companion.getClass();
            explanationsLogger.a(ExplanationsEventLog.Companion.a("explanations_click_featured_content", aVar));
            return;
        }
        explanationsLogger.getClass();
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        Intrinsics.checkNotNullParameter(eventData, "eventData");
        ExplanationsEventLog.Companion companion2 = ExplanationsEventLog.b;
        com.quizlet.eventlogger.features.explanations.a aVar2 = new com.quizlet.eventlogger.features.explanations.a(1, eventData, explanationsLogger, screenName);
        companion2.getClass();
        explanationsLogger.a(ExplanationsEventLog.Companion.a("explanations_click_recent_content", aVar2));
    }
}
