package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.quizlet.data.model.NotesToValueInfo;
import com.quizlet.data.model.TitleInfo;
import com.quizlet.data.model.User;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class V5 {
    public static final void a(Function1 function1, Function1 function12, Function0 function0, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b bVar, InterfaceC0806l interfaceC0806l, int i) {
        boolean z;
        com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b bVar2;
        int i2;
        androidx.compose.ui.n nVar;
        com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b bVar3;
        androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(972265765);
        int i3 = i | (c0814p.f(nVar2) ? 4 : 2) | (c0814p.h(function1) ? 32 : 16) | (c0814p.h(function12) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024) | 8192;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            bVar3 = bVar;
        } else {
            c0814p.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                z = false;
                Object objE = AbstractC3417z1.e(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                bVar2 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b) objE;
                i2 = i3 & (-57345);
            } else {
                c0814p.Q();
                z = false;
                i2 = i3 & (-57345);
                bVar2 = bVar;
            }
            c0814p.q();
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o oVar = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o) bVar2;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(oVar.i, c0814p);
            kotlinx.coroutines.flow.d0 d0Var = oVar.j;
            c0814p.X(1414113791);
            boolean z2 = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32 ? true : z;
            Object objI = c0814p.I();
            if (z2 || objI == v) {
                objI = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.E(function1, null);
                c0814p.i0(objI);
            }
            c0814p.p(z);
            c0814p.X(-827048655);
            AbstractC0809m0 abstractC0809m0 = androidx.lifecycle.compose.g.a;
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zH = c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(b) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                nVar = nVar2;
                objI2 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.B(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            } else {
                nVar = nVar2;
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI2);
            c0814p.p(false);
            kotlinx.coroutines.flow.d0 d0Var2 = oVar.k;
            c0814p.X(1414116575);
            boolean z3 = (i2 & 896) == 256;
            Object objI3 = c0814p.I();
            if (z3 || objI3 == v) {
                objI3 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.F(function12, null);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j2 = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            InterfaceC0773a0 interfaceC0773a0D2 = C0776c.D((Function2) objI3, c0814p);
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j2) | c0814p.h(d0Var2) | c0814p.f(interfaceC0773a0D2);
            Object objI4 = c0814p.I();
            if (zF || objI4 == v) {
                objI4 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.D(interfaceC0773a0D2, j2, null, d0Var2);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI4);
            c0814p.p(false);
            long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
            c0814p.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            AbstractC0725t3.a(nVar, androidx.compose.runtime.internal.e.e(1719410409, new androidx.navigation.compose.o(22, bVar2, function0), c0814p), null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(-386699148, new com.quizlet.assembly.compose.input.m(18, bVar2, interfaceC0773a0G), c0814p), c0814p, (i2 & 14) | 805306416, 188);
            c0814p = c0814p;
            bVar3 = bVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i((Object) function1, (Object) function12, function0, (Object) bVar3, i, 13);
        }
    }

    public static final float b(float f) {
        float fIntBitsToFloat = Float.intBitsToFloat(((int) ((Float.floatToRawIntBits(f) & 8589934591L) / 3)) + 709952852);
        float f2 = fIntBitsToFloat - ((fIntBitsToFloat - (f / (fIntBitsToFloat * fIntBitsToFloat))) * 0.33333334f);
        return f2 - ((f2 - (f / (f2 * f2))) * 0.33333334f);
    }

    public static final float c(float f, float f2, float f3) {
        return (f3 * f2) + ((1 - f3) * f);
    }

    public static final int d(int i, float f, int i2) {
        return i + ((int) Math.round((i2 - i) * f));
    }

    public static final com.quizlet.ui.models.content.listitem.f e(NotesToValueInfo notesToValueInfo, long j) {
        Intrinsics.checkNotNullParameter(notesToValueInfo, "<this>");
        String str = notesToValueInfo.a;
        TitleInfo titleInfo = notesToValueInfo.c;
        String str2 = titleInfo != null ? titleInfo.c : null;
        if (str2 == null) {
            str2 = "";
        }
        User user = notesToValueInfo.h;
        return new com.quizlet.ui.models.content.listitem.f(str, str2, user.b, user.a == j);
    }
}
