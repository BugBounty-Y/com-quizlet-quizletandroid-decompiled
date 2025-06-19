package com.google.android.gms.internal.measurement;

import android.content.Context;
import android.util.Log;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3223o5;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.R4;
import java.util.Set;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.measurement.s1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3053s1 {
    public static com.onetrust.otpublishers.headless.UI.TVUI.datautils.d a = null;
    public static int b = 3;

    public static final void a(kotlinx.collections.immutable.b items, androidx.compose.ui.n nVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(items, "items");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(764327570);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(items) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | 48;
        if ((i & 384) == 0) {
            i3 |= c0814p.h(function1) ? 256 : 128;
        }
        int i4 = i3;
        if ((i4 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p.X(262504666);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = new com.quizlet.db.data.models.persisted.types.a(26);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            androidx.compose.material3.windowsizeclass.b bVarG = AbstractC3205m5.g(c0814p);
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            int i5 = bVarG.a == 2 ? 5 : 2;
            int i6 = AbstractC3205m5.g(c0814p).a == 2 ? 5 : 4;
            float fA = AbstractC3223o5.a(c0814p, i5);
            com.quizlet.themes.m.g.t();
            R4.a(nVar3, null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(1487280152, new com.quizlet.features.achievements.ui.composables.I(fA - com.quizlet.ui.resources.designsystem.generated.j.k, i5, i6, interfaceC0773a0, function1, items), c0814p), c0814p, (i4 >> 3) & 14, 1022);
            c0814p = c0814p;
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 9, items, nVar2, function1);
        }
    }

    public static CharSequence b(com.quizlet.qutils.string.g gVar, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1600340972);
        CharSequence charSequenceC = gVar.c((Context) c0814p.j(AndroidCompositionLocals_androidKt.b));
        c0814p.p(false);
        return charSequenceC;
    }

    public static void c(String str, String str2) {
        if (f(6, str)) {
            Log.e(str, str2);
        }
    }

    public static void d(String str, String str2, Throwable th) {
        if (f(6, str)) {
            Log.e(str, str2, th);
        }
    }

    public static String e(com.quizlet.qutils.string.g gVar, Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        return gVar.c(context).toString();
    }

    public static boolean f(int i, String str) {
        return b <= i || Log.isLoggable(str, i);
    }

    public static String g(com.quizlet.qutils.string.g gVar, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(997161632);
        String string = gVar.d(c0814p, 0).toString();
        c0814p.p(false);
        return string;
    }

    public static void h(String str, String str2) {
        if (f(5, str)) {
            Log.w(str, str2);
        }
    }

    public static void i(String str, String str2, Throwable th) {
        if (f(5, str)) {
            Log.w(str, str2, th);
        }
    }
}
