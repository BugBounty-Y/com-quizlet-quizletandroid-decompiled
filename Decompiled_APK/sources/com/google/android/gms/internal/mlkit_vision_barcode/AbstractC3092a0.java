package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.a0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3092a0 {
    public static final /* synthetic */ int a = 0;

    public static final void a(androidx.compose.foundation.contextmenu.o oVar) {
        ((androidx.compose.runtime.L0) oVar.a).setValue(androidx.compose.foundation.contextmenu.l.a);
    }

    public static final String b(com.quizlet.report.data.n nVar, InterfaceC0806l interfaceC0806l) {
        String strH;
        int i;
        int i2;
        Intrinsics.checkNotNullParameter(nVar, "<this>");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1008609153);
        if (Intrinsics.b(nVar, com.quizlet.report.data.l.a)) {
            i = -237399384;
            i2 = R.string.why_are_you_reporting;
        } else {
            if (!Intrinsics.b(nVar, com.quizlet.report.data.j.a)) {
                if (Intrinsics.b(nVar, com.quizlet.report.data.k.a)) {
                    c0814p.X(1230724003);
                    c0814p.p(false);
                } else {
                    if (!Intrinsics.b(nVar, com.quizlet.report.data.m.a)) {
                        c0814p.X(-237391763);
                        c0814p.p(false);
                        throw new IllegalArgumentException("Report options: " + nVar + " not implemented yet. Do it.");
                    }
                    c0814p.X(1230766659);
                    c0814p.p(false);
                }
                strH = null;
                c0814p.p(false);
                return strH;
            }
            i = -237396628;
            i2 = R.string.why_is_this_inappropriate;
        }
        strH = com.google.android.gms.measurement.internal.Z.h(c0814p, i, i2, c0814p, false);
        c0814p.p(false);
        return strH;
    }
}
