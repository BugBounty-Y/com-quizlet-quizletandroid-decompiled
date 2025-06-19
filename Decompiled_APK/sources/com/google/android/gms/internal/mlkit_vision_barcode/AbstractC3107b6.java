package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.ComposeView;
import com.comscore.streaming.ContentType;
import com.quizlet.features.achievements.ui.composables.C4218e;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.b6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3107b6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(androidx.lifecycle.Y shouldShow, Function0 onPositive, androidx.compose.ui.n nVar, int i, int i2, InterfaceC0806l interfaceC0806l, int i3) {
        androidx.compose.ui.n nVar2;
        androidx.compose.ui.n nVar3;
        Intrinsics.checkNotNullParameter(shouldShow, "shouldShow");
        Intrinsics.checkNotNullParameter(onPositive, "onPositive");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2096503665);
        int i4 = i3 | (c0814p.h(shouldShow) ? 4 : 2) | (c0814p.h(onPositive) ? 32 : 16) | 384 | (c0814p.d(i) ? 2048 : 1024) | (c0814p.d(i2) ? 16384 : 8192);
        if ((i4 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar;
        } else {
            c0814p.S();
            if ((i3 & 1) == 0 || c0814p.w()) {
                nVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p.Q();
                nVar2 = nVar;
            }
            c0814p.q();
            if (Intrinsics.b(J4.b(shouldShow, shouldShow.d(), c0814p, i4 & 14).getValue(), Boolean.TRUE)) {
                com.google.android.gms.internal.mlkit_vision_document_scanner.W5.a(R.string.got_it, i2, androidx.compose.ui.platform.N.G(nVar2, "offline_warning_dialog"), onPositive, null, null, Integer.valueOf(i), null, c0814p, ((i4 >> 9) & ContentType.LONG_FORM_ON_DEMAND) | ((i4 << 6) & 7168) | ((i4 << 9) & 3670016), 176);
            }
            nVar3 = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4218e(shouldShow, onPositive, nVar3, i, i2, i3);
        }
    }

    public static AbstractC3107b6 b(int i, double[] dArr, double[][] dArr2) {
        if (dArr.length == 1) {
            i = 2;
        }
        if (i == 0) {
            return new androidx.constraintlayout.core.motion.utils.h(dArr, dArr2);
        }
        if (i == 2) {
            double d = dArr[0];
            double[] dArr3 = dArr2[0];
            androidx.constraintlayout.core.motion.utils.c cVar = new androidx.constraintlayout.core.motion.utils.c();
            cVar.b = d;
            cVar.c = dArr3;
            return cVar;
        }
        androidx.constraintlayout.core.motion.utils.g gVar = new androidx.constraintlayout.core.motion.utils.g();
        int length = dArr2[0].length;
        gVar.d = new double[length];
        gVar.b = dArr;
        gVar.c = dArr2;
        if (length > 2) {
            double d2 = 0.0d;
            int i2 = 0;
            while (true) {
                double d3 = d2;
                if (i2 >= dArr.length) {
                    break;
                }
                double d4 = dArr2[i2][0];
                if (i2 > 0) {
                    Math.hypot(d4 - d2, d4 - d3);
                }
                i2++;
                d2 = d4;
            }
        }
        return gVar;
    }

    public static final void h(ComposeView composeView, androidx.lifecycle.Y shouldShow, Function0 onPositive, int i, int i2) {
        Intrinsics.checkNotNullParameter(composeView, "<this>");
        Intrinsics.checkNotNullParameter(shouldShow, "shouldShow");
        Intrinsics.checkNotNullParameter(onPositive, "onPositive");
        composeView.setContent(new androidx.compose.runtime.internal.d(true, -1340939107, new com.quizlet.uicommon.ui.common.dialogs.info.g(shouldShow, onPositive, i, i2, 1)));
    }

    public abstract double c(double d);

    public abstract void d(double d, double[] dArr);

    public abstract void e(double d, float[] fArr);

    public abstract void f(double d, double[] dArr);

    public abstract double[] g();
}
