package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.AdvertisementType;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3125d6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class l7 {
    public static final /* synthetic */ int a = 0;

    public static final void a(androidx.compose.ui.n nVar, boolean z, String str, com.quizlet.features.infra.folder.menu.viewmodel.n nVar2, com.quizlet.features.infra.folder.save.viewmodel.c cVar, Function0 function0, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.features.infra.folder.save.viewmodel.c cVar2;
        androidx.compose.ui.n nVar3;
        C0814p c0814p;
        androidx.compose.ui.n nVar4;
        com.quizlet.features.infra.folder.save.viewmodel.c cVar3;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1895519524);
        if (((i | 6 | (c0814p2.g(z) ? 32 : 16) | (c0814p2.f(str) ? 256 : 128) | (c0814p2.h(nVar2) ? 2048 : 1024) | 8192 | (c0814p2.h(function0) ? 131072 : 65536) | (c0814p2.h(function1) ? 1048576 : 524288)) & 599187) == 599186 && c0814p2.x()) {
            c0814p2.Q();
            nVar4 = nVar;
            c0814p = c0814p2;
            cVar3 = cVar;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                androidx.compose.ui.n nVar5 = androidx.compose.ui.n.b;
                c0814p2.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p2);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p2);
                c0814p2.Y(1729797275);
                androidx.lifecycle.w0 w0VarE = AbstractC3417z1.e(com.quizlet.features.infra.folder.save.viewmodel.c.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p2);
                c0814p2.p(false);
                c0814p2.p(false);
                cVar2 = (com.quizlet.features.infra.folder.save.viewmodel.c) w0VarE;
                nVar3 = nVar5;
            } else {
                c0814p2.Q();
                nVar3 = nVar;
                cVar2 = cVar;
            }
            c0814p2.q();
            androidx.compose.ui.n nVar6 = nVar3;
            AbstractC3691o6.b(com.quizlet.explanations.questiondetail.ui.composables.b.a, nVar6, 0L, 0L, 0L, null, androidx.compose.runtime.internal.e.e(223284014, new com.quizlet.explanations.questiondetail.ui.composables.m(0, function0), c0814p2), androidx.compose.runtime.internal.e.e(-994658267, new com.quizlet.explanations.questiondetail.ui.composables.n(z, str, cVar2, nVar2, function1), c0814p2), c0814p2, 14155830, 60);
            c0814p = c0814p2;
            nVar4 = nVar6;
            cVar3 = cVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.k(nVar4, z, str, nVar2, cVar3, function0, function1, i);
        }
    }

    public static final void b(Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.assembly.compose.menu.s sVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(426941773);
        int i3 = (c0814p.h(function1) ? 4 : 2) | i;
        if ((i3 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            com.quizlet.assembly.compose.menu.s sVarB = K5.b(c0814p);
            ArrayList arrayList = new ArrayList();
            arrayList.add(com.quizlet.explanations.questiondetail.data.c.a);
            arrayList.add(com.quizlet.explanations.questiondetail.data.b.a);
            c0814p.X(-49011251);
            ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                com.quizlet.explanations.questiondetail.data.d dVar = (com.quizlet.explanations.questiondetail.data.d) it2.next();
                arrayList2.add(new com.quizlet.assembly.compose.menu.o(dVar, dVar.a(c0814p), dVar.b(c0814p), null, false, null, false, 248));
            }
            c0814p.p(false);
            sVarB.c(arrayList2, true);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarB = com.quizlet.ui.resources.icons.d.B(c0814p);
            C4076a c4076a = C4076a.e;
            String strD = AbstractC3106b5.d(c0814p, R.string.options);
            c0814p.X(-426120578);
            boolean zH = c0814p.h(sVarB);
            Object objI = c0814p.I();
            if (zH || objI == v) {
                androidx.activity.K k = new androidx.activity.K(0, sVarB, com.quizlet.assembly.compose.menu.s.class, "show", "show()V", 0, 17);
                i2 = i3;
                sVar = sVarB;
                c0814p.i0(k);
                objI = k;
            } else {
                i2 = i3;
                sVar = sVarB;
            }
            c0814p.p(false);
            AbstractC3578a5.a(bVarB, strD, null, (Function0) ((kotlin.reflect.f) objI), false, c4076a, null, 0L, c0814p, 0, AdvertisementType.ON_DEMAND_MID_ROLL);
            c0814p = c0814p;
            I5.a(sVar, function1, com.onetrust.otpublishers.headless.Internal.Helper.h.x(), null, 0, c0814p, (i2 << 3) & ContentType.LONG_FORM_ON_DEMAND, 24);
            AbstractC3125d6.a(null, c0814p, 0, 1);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.l(function1, i, 0);
        }
    }
}
