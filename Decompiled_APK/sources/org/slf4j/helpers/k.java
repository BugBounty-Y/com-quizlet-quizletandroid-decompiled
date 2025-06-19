package org.slf4j.helpers;

import android.content.Context;
import android.content.res.Resources;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.q;
import com.braze.r;
import com.comscore.streaming.AdvertisementType;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3125d6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3578a5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.I5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K5;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.assembly.compose.menu.o;
import com.quizlet.assembly.compose.menu.s;
import com.quizlet.generated.enums.y1;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.collections.C;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class k {
    public static j a = null;
    public static boolean b = false;

    public static final void a(boolean z, Function1 function1, Function1 function12, InterfaceC0806l interfaceC0806l, int i) {
        s sVar;
        Object k;
        boolean z2;
        boolean z3;
        Function1 function13;
        Function1 function14;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1900932251);
        int i2 = (c0814p2.g(z) ? 4 : 2) | i | (c0814p2.h(function1) ? 32 : 16) | (c0814p2.h(function12) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            function14 = function1;
            function13 = function12;
            c0814p = c0814p2;
        } else {
            V v = C0804k.a;
            s sVarB = K5.b(c0814p2);
            ArrayList arrayList = new ArrayList();
            com.quizlet.explanations.textbook.data.f fVar = com.quizlet.explanations.textbook.data.f.a;
            arrayList.add(fVar);
            sVarB.c(d(arrayList, c0814p2), true);
            s sVarB2 = K5.b(c0814p2);
            ArrayList arrayList2 = new ArrayList();
            arrayList2.add(fVar);
            arrayList2.add(com.quizlet.explanations.textbook.data.e.a);
            sVarB2.c(d(arrayList2, c0814p2), true);
            n nVar = n.b;
            K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            q qVarC = androidx.compose.ui.a.c(c0814p2, nVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, kE, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            com.quizlet.themes.e.a(c0814p2).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarB = com.quizlet.ui.resources.icons.d.B(c0814p2);
            C4076a c4076a = C4076a.e;
            String strD = AbstractC3106b5.d(c0814p2, R.string.options);
            c0814p2.X(732430534);
            boolean zH = ((i2 & 14) == 4) | c0814p2.h(sVarB2) | c0814p2.h(sVarB);
            Object objI = c0814p2.I();
            Object obj = objI;
            if (zH || objI == v) {
                r rVar = new r(z, sVarB2, sVarB, 5);
                c0814p2.i0(rVar);
                obj = rVar;
            }
            c0814p2.p(false);
            AbstractC3578a5.a(bVarB, strD, null, (Function0) obj, false, c4076a, null, 0L, c0814p2, 0, AdvertisementType.ON_DEMAND_MID_ROLL);
            com.quizlet.assembly.compose.menu.r rVarX = com.onetrust.otpublishers.headless.Internal.Helper.h.x();
            c0814p2.X(732444384);
            boolean zH2 = c0814p2.h(sVarB);
            Object objI2 = c0814p2.I();
            if (zH2 || objI2 == v) {
                sVar = sVarB;
                androidx.activity.K k2 = new androidx.activity.K(0, sVar, s.class, "hide", "hide()V", 0, 21);
                c0814p2.i0(k2);
                objI2 = k2;
            } else {
                sVar = sVarB;
            }
            c0814p2.p(false);
            C0814p c0814p3 = c0814p2;
            I5.a(sVar, function1, rVarX, (Function0) ((kotlin.reflect.f) objI2), 0, c0814p3, i2 & ContentType.LONG_FORM_ON_DEMAND, 16);
            com.quizlet.assembly.compose.menu.r rVarX2 = com.onetrust.otpublishers.headless.Internal.Helper.h.x();
            c0814p3.X(732453088);
            boolean zH3 = c0814p3.h(sVarB2);
            Object objI3 = c0814p3.I();
            if (zH3 || objI3 == v) {
                z2 = true;
                z3 = false;
                k = new androidx.activity.K(0, sVarB2, s.class, "hide", "hide()V", 0, 22);
                c0814p3.i0(k);
            } else {
                k = objI3;
                z3 = false;
                z2 = true;
            }
            c0814p3.p(z3);
            boolean z4 = z2;
            boolean z5 = z3;
            function13 = function12;
            function14 = function1;
            I5.a(sVarB2, function13, rVarX2, (Function0) ((kotlin.reflect.f) k), 0, c0814p3, (i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND, 16);
            AbstractC3125d6.a(null, c0814p3, z5 ? 1 : 0, z4 ? 1 : 0);
            c0814p3.p(z4);
            c0814p = c0814p3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.textbook.ui.composables.h(z, function14, function13, i);
        }
    }

    public static final void b(n nVar, boolean z, Function0 function0, boolean z2, boolean z3, String str, y1 y1Var, com.quizlet.features.infra.folder.menu.viewmodel.n nVar2, Function1 function1, Function1 function12, InterfaceC0806l interfaceC0806l, int i) {
        n nVar3;
        n nVar4;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(392886209);
        if (((i | 6 | (c0814p.g(z) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128) | (c0814p.g(z2) ? 2048 : 1024) | (c0814p.g(z3) ? 16384 : 8192) | (c0814p.f(str) ? 131072 : 65536) | (c0814p.f(y1Var) ? 1048576 : 524288) | (c0814p.h(nVar2) ? 8388608 : 4194304) | (c0814p.h(function1) ? 67108864 : 33554432) | (c0814p.h(function12) ? 536870912 : 268435456)) & 306783379) == 306783378 && c0814p.x()) {
            c0814p.Q();
            nVar4 = nVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                nVar3 = n.b;
            } else {
                c0814p.Q();
                nVar3 = nVar;
            }
            c0814p.q();
            n nVar5 = nVar3;
            AbstractC3691o6.b(com.quizlet.explanations.textbook.ui.composables.b.a, nVar5, 0L, 0L, 0L, null, androidx.compose.runtime.internal.e.e(-1212699701, new com.quizlet.explanations.textbook.ui.composables.i(z, function0, 0), c0814p), androidx.compose.runtime.internal.e.e(2002259394, new com.quizlet.explanations.textbook.ui.composables.j(z3, y1Var, str, nVar2, z2, function1, function12), c0814p), c0814p, 14155830, 60);
            nVar4 = nVar5;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.textbook.ui.composables.g(nVar4, z, function0, z2, z3, str, y1Var, nVar2, function1, function12, i);
        }
    }

    public static final String c(boolean z, InterfaceC0806l interfaceC0806l) throws Resources.NotFoundException {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-559036786);
        c0814p.X(111556608);
        if (!z) {
            c0814p.p(false);
            String strD = com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b.d(c0814p, R.string.engagement_widget_quote_inactive_streak);
            c0814p.p(false);
            return strD;
        }
        c0814p.X(1815240988);
        String[] stringArray = ((Context) c0814p.j(androidx.glance.j.b)).getResources().getStringArray(R.array.engagement_widget_quote_active_streak);
        Intrinsics.checkNotNullExpressionValue(stringArray, "getStringArray(...)");
        c0814p.p(false);
        kotlin.random.d random = kotlin.random.e.a;
        Intrinsics.checkNotNullParameter(stringArray, "<this>");
        Intrinsics.checkNotNullParameter(random, "random");
        if (stringArray.length == 0) {
            throw new NoSuchElementException("Array is empty.");
        }
        int length = stringArray.length;
        random.getClass();
        String str = stringArray[kotlin.random.e.b.d(length)];
        c0814p.p(false);
        c0814p.p(false);
        return str;
    }

    public static final ArrayList d(ArrayList arrayList, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1929328545);
        ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            com.quizlet.explanations.textbook.data.g gVar = (com.quizlet.explanations.textbook.data.g) it2.next();
            arrayList2.add(new o(gVar, gVar.a(c0814p), gVar.b(c0814p), null, false, null, false, 248));
        }
        c0814p.p(false);
        return arrayList2;
    }
}
