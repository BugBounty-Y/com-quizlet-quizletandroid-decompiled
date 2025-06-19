package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.os.StrictMode;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.ads.C1744Ob;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.settings.viewmodels.C4449g;
import com.quizlet.quizletandroid.R;
import java.util.WeakHashMap;
import java.util.concurrent.Callable;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class X2 {
    public static final void a(C4449g c4449g, Function0 onUpAction, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C4449g c4449g2;
        Intrinsics.checkNotNullParameter(onUpAction, "onUpAction");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(370773594);
        int i3 = i | 2 | (c0814p.h(onUpAction) ? 32 : 16);
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            c4449g2 = c4449g;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                androidx.lifecycle.w0 w0VarE = AbstractC3417z1.e(C4449g.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i2 = i3 & (-15);
                c4449g2 = (C4449g) w0VarE;
            } else {
                c0814p.Q();
                i2 = i3 & (-15);
                c4449g2 = c4449g;
            }
            c0814p.q();
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(c4449g2.f, c0814p);
            Object[] objArr = new Object[0];
            c0814p.X(459013157);
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            if (objI == obj) {
                objI = new com.quizlet.features.settings.composables.changeusername.c(2);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            Object objD = com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            c0814p = c0814p;
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objD;
            kotlinx.coroutines.flow.d0 d0Var = c4449g2.b;
            c0814p.X(459015807);
            boolean z = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI2 = c0814p.I();
            if (z || objI2 == obj) {
                objI2 = new com.quizlet.features.settings.composables.changeusername.j(onUpAction, null);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI3 = c0814p.I();
            if (zF || objI3 == obj) {
                objI3 = new com.quizlet.features.settings.composables.changeusername.i(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            com.quizlet.features.settings.data.states.l lVar = (com.quizlet.features.settings.data.states.l) AbstractC4178x.k(unit, (Function2) objI3, c0814p, false, interfaceC0773a0M);
            String str = (String) interfaceC0773a0.getValue();
            c0814p.X(459020981);
            boolean zH = c0814p.h(c4449g2) | c0814p.f(interfaceC0773a0);
            Object objI4 = c0814p.I();
            if (zH || objI4 == obj) {
                objI4 = new com.quizlet.features.settings.composables.changeusername.a(c4449g2, interfaceC0773a0, 1);
                c0814p.i0(objI4);
            }
            Function0 function0 = (Function0) objI4;
            boolean zR = AbstractC4178x.r(c0814p, false, 459023383, interfaceC0773a0);
            Object objI5 = c0814p.I();
            if (zR || objI5 == obj) {
                objI5 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a0, 19);
                c0814p.i0(objI5);
            }
            c0814p.p(false);
            c(lVar, str, onUpAction, function0, (Function1) objI5, c0814p, (i2 << 3) & 896);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.changeusername.b(c4449g2, onUpAction, i, 1);
        }
    }

    public static final void b(Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function03;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-19909376);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i | (c0814p.h(function02) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function03 = function0;
        } else {
            function03 = function0;
            N2.b(null, AbstractC3106b5.d(c0814p, R.string.change_username_title), 0L, null, function03, androidx.compose.runtime.internal.e.e(-1523285024, new com.quizlet.features.infra.folder.create.coursefolder.composable.k(8, function02), c0814p), c0814p, ((i2 << 12) & 57344) | 196608, 13);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.upload.composables.common.d(function03, function02, i, 3);
        }
    }

    public static final void c(com.quizlet.features.settings.data.states.l lVar, String str, Function0 function0, Function0 function02, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        int i3 = 1;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1540312741);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p2.f(lVar) : c0814p2.h(lVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(str) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function0) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.h(function02) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.h(function1) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            long jG = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g();
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(null, androidx.compose.runtime.internal.e.e(-197200865, new com.quizlet.features.notes.upload.composables.upload.b(i3, function0, function02), c0814p2), null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(457673066, new com.quizlet.features.settings.composables.changeusername.g(lVar, str, function1, i3), c0814p2), c0814p, 805306416, 189);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(lVar, str, function0, function02, function1, i, 13);
        }
    }

    public static Object d(Context context, Callable callable) {
        try {
            StrictMode.ThreadPolicy threadPolicy = StrictMode.getThreadPolicy();
            try {
                StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder(threadPolicy).permitDiskReads().permitDiskWrites().build());
                return callable.call();
            } finally {
                StrictMode.setThreadPolicy(threadPolicy);
            }
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.i.f("Unexpected exception.", th);
            C1744Ob.a(context).d("StrictModeUtil.runWithLaxStrictMode", th);
            return null;
        }
    }
}
