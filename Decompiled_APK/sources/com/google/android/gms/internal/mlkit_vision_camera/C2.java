package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.work.impl.C1433e;
import androidx.work.impl.InterfaceC1435g;
import androidx.work.impl.WorkDatabase;
import androidx.work.impl.WorkDatabase_Impl;
import com.comscore.streaming.ContentType;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class C2 {
    public static final String a = "\ufeff";
    public static final String b = " ";
    public static final char c = 8203;
    public static final String d = "\u200b";
    public static final char e = 65532;
    public static final String f = "￼";
    public static final char g = '\n';
    public static final String h = "\n";
    public static final char i = 8203;
    public static final String j = "\u200b";

    public static final void a(com.quizlet.features.questiontypes.basequestion.data.a viewGradedState, com.quizlet.features.questiontypes.basequestion.data.a aVar, Function1 showSheetAction, Function0 onAutoAdvance, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        Intrinsics.checkNotNullParameter(viewGradedState, "viewGradedState");
        Intrinsics.checkNotNullParameter(showSheetAction, "showSheetAction");
        Intrinsics.checkNotNullParameter(onAutoAdvance, "onAutoAdvance");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1729354939);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.f(viewGradedState) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.f(aVar) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p.h(showSheetAction) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p.h(onAutoAdvance) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.X(-1565241295);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                c0814p.i0(showSheetAction);
                objI = showSheetAction;
            }
            Function1 function1 = (Function1) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(-1565239665, c0814p, false);
            if (objG == v) {
                c0814p.i0(onAutoAdvance);
                objG = onAutoAdvance;
            }
            Function0 function0 = (Function0) objG;
            c0814p.p(false);
            c0814p.X(-1565237604);
            boolean z = (i3 & 14) == 4;
            Object objI2 = c0814p.I();
            if (z || objI2 == v) {
                objI2 = new com.quizlet.features.questiontypes.basequestion.d(function1, viewGradedState, null);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, viewGradedState, (Function2) objI2);
            c0814p.X(-1565234018);
            boolean z2 = (i3 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI3 = c0814p.I();
            if (z2 || objI3 == v) {
                objI3 = new com.quizlet.features.questiontypes.basequestion.e(aVar, function0, null);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            C0776c.f(c0814p, aVar, (Function2) objI3);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i((Object) viewGradedState, (Object) aVar, showSheetAction, (Object) onAutoAdvance, i2, 21);
        }
    }

    public static final void b(androidx.work.impl.r rVar, String str) {
        androidx.work.impl.F fB;
        WorkDatabase workDatabase = rVar.c;
        Intrinsics.checkNotNullExpressionValue(workDatabase, "workManagerImpl.workDatabase");
        androidx.work.impl.model.t tVarU = workDatabase.u();
        androidx.work.impl.model.c cVarF = workDatabase.f();
        ArrayList arrayListK = kotlin.collections.B.k(str);
        while (!arrayListK.isEmpty()) {
            String str2 = (String) kotlin.collections.G.A(arrayListK);
            androidx.work.N n = tVarU.n(str2);
            if (n != androidx.work.N.c && n != androidx.work.N.d) {
                WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) tVarU.a;
                workDatabase_Impl.b();
                androidx.work.impl.model.h hVar = (androidx.work.impl.model.h) tVarU.e;
                androidx.sqlite.db.framework.i iVarA = hVar.a();
                iVarA.g(1, str2);
                try {
                    workDatabase_Impl.c();
                    try {
                        iVarA.a();
                        workDatabase_Impl.p();
                    } finally {
                    }
                } finally {
                    hVar.n(iVarA);
                }
            }
            arrayListK.addAll(cVarF.e(str2));
        }
        C1433e c1433e = rVar.f;
        Intrinsics.checkNotNullExpressionValue(c1433e, "workManagerImpl.processor");
        synchronized (c1433e.k) {
            androidx.work.z.c().getClass();
            c1433e.i.add(str);
            fB = c1433e.b(str);
        }
        C1433e.d(fB, 1);
        Iterator it2 = rVar.e.iterator();
        while (it2.hasNext()) {
            ((InterfaceC1435g) it2.next()).e(str);
        }
    }
}
