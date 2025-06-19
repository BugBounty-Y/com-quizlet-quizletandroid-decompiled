package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.text.format.DateFormat;
import androidx.compose.foundation.C0473q;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.material3.C0585a1;
import androidx.compose.material3.C0602d0;
import androidx.compose.material3.C0710r0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.quizlet.login.common.interactors.data.C4590a;
import com.quizlet.quizletandroid.R;
import com.quizlet.ui.compose.AbstractC4827u;
import com.skydoves.balloon.internals.DefinitionKt;
import java.text.SimpleDateFormat;
import java.time.ZoneId;
import java.util.Calendar;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* loaded from: classes2.dex */
public abstract class C {
    public static final void a(Function1 function1, C4590a calendarData, androidx.compose.ui.q qVar, com.quizlet.time.b bVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.time.b bVar2;
        Object bVar3;
        InterfaceC0773a0 interfaceC0773a0;
        androidx.compose.material3.windowsizeclass.b bVar4;
        InterfaceC0773a0 interfaceC0773a02;
        char c;
        C0585a1 c0585a1;
        String str;
        boolean z;
        C0814p c0814p;
        com.quizlet.time.b bVar5;
        C0814p c0814p2;
        Function1 onValueChange = function1;
        int i3 = 4;
        Intrinsics.checkNotNullParameter(onValueChange, "onValueChange");
        Intrinsics.checkNotNullParameter(calendarData, "calendarData");
        C0814p c0814p3 = (C0814p) interfaceC0806l;
        c0814p3.Z(-498374353);
        int i4 = i | (c0814p3.h(onValueChange) ? 4 : 2) | (c0814p3.f(calendarData) ? 32 : 16) | (c0814p3.f(qVar) ? 256 : 128) | 1024;
        if ((i4 & 1171) == 1170 && c0814p3.x()) {
            c0814p3.Q();
            bVar5 = bVar;
            c0814p2 = c0814p3;
        } else {
            c0814p3.S();
            if ((i & 1) == 0 || c0814p3.w()) {
                i2 = i4 & (-7169);
                bVar2 = new com.quizlet.time.b();
            } else {
                c0814p3.Q();
                i2 = i4 & (-7169);
                bVar2 = bVar;
            }
            c0814p3.q();
            androidx.compose.material3.windowsizeclass.b bVarG = AbstractC3205m5.g(c0814p3);
            c0814p3.X(-1196770211);
            Object objI = c0814p3.I();
            androidx.compose.runtime.V v = C0804k.a;
            Object obj = objI;
            if (objI == v) {
                InterfaceC0773a0 interfaceC0773a0Z = C0776c.z(null);
                c0814p3.i0(interfaceC0773a0Z);
                obj = interfaceC0773a0Z;
            }
            InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) obj;
            Object objG = com.google.android.gms.measurement.internal.Z.g(-1196768290, c0814p3, false);
            Object obj2 = objG;
            if (objG == v) {
                InterfaceC0773a0 interfaceC0773a0Z2 = C0776c.z(Boolean.FALSE);
                c0814p3.i0(interfaceC0773a0Z2);
                obj2 = interfaceC0773a0Z2;
            }
            InterfaceC0773a0 interfaceC0773a04 = (InterfaceC0773a0) obj2;
            c0814p3.p(false);
            com.quizlet.login.common.ui.c cVar = new com.quizlet.login.common.ui.c(calendarData);
            float f = androidx.compose.material3.Z0.a;
            IntRange intRange = C0710r0.a;
            Locale localeQ = androidx.compose.material3.Z1.q(c0814p3);
            Object[] objArr = new Object[0];
            com.quizlet.data.repository.explanations.myexplanations.a aVarB = com.google.android.gms.internal.mlkit_vision_barcode.K4.b(C0602d0.v, new androidx.compose.foundation.text.selection.n0(i3, cVar, localeQ));
            boolean zF = c0814p3.f(null) | c0814p3.f(null) | c0814p3.h(intRange) | c0814p3.d(0) | c0814p3.f(cVar) | c0814p3.h(localeQ);
            Object objI2 = c0814p3.I();
            Object obj3 = objI2;
            if (zF || objI2 == v) {
                C0473q c0473q = new C0473q(intRange, cVar, localeQ, 7);
                c0814p3.i0(c0473q);
                obj3 = c0473q;
            }
            C0585a1 c0585a12 = (C0585a1) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, aVarB, (Function0) obj3, c0814p3, 0, 4);
            ((androidx.compose.runtime.L0) c0585a12.c).setValue(cVar);
            Long lB = c0585a12.b();
            c0814p3.X(-1196750376);
            boolean zF2 = c0814p3.f(c0585a12) | ((i2 & 14) == 4);
            Object objI3 = c0814p3.I();
            if (zF2 || objI3 == v) {
                interfaceC0773a0 = interfaceC0773a03;
                bVar4 = bVarG;
                interfaceC0773a02 = interfaceC0773a04;
                c = 2;
                bVar3 = new com.quizlet.login.common.ui.b(c0585a12, onValueChange, interfaceC0773a0, interfaceC0773a02, null);
                c0585a1 = c0585a12;
                onValueChange = onValueChange;
                c0814p3.i0(bVar3);
            } else {
                bVar3 = objI3;
                bVar4 = bVarG;
                interfaceC0773a0 = interfaceC0773a03;
                c0585a1 = c0585a12;
                interfaceC0773a02 = interfaceC0773a04;
                c = 2;
            }
            c0814p3.p(false);
            C0776c.g(lB, onValueChange, (Function2) bVar3, c0814p3);
            c0814p3.X(-1196739243);
            Object objI4 = c0814p3.I();
            Object obj4 = objI4;
            if (objI4 == v) {
                com.quizlet.features.practicetest.detail.composables.f fVar = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a02, 15);
                c0814p3.i0(fVar);
                obj4 = fVar;
            }
            Function0 onRelease = (Function0) obj4;
            c0814p3.p(false);
            Intrinsics.checkNotNullParameter(onRelease, "onRelease");
            c0814p3.X(1697250946);
            c0814p3.X(-19992760);
            Object objI5 = c0814p3.I();
            Object objI6 = objI5;
            if (objI5 == v) {
                objI6 = androidx.compose.animation.d0.i(c0814p3);
            }
            androidx.compose.foundation.interaction.l lVar = (androidx.compose.foundation.interaction.l) objI6;
            c0814p3.p(false);
            androidx.compose.material3.windowsizeclass.b bVar6 = bVar4;
            if (C0776c.l(lVar.b(), new androidx.compose.foundation.interaction.n(new androidx.compose.foundation.interaction.o(0L)), null, c0814p3, 0, 2).getValue() instanceof androidx.compose.foundation.interaction.p) {
                onRelease.invoke();
                lVar.a(new androidx.compose.foundation.interaction.n(new androidx.compose.foundation.interaction.o(0L)));
            }
            c0814p3.p(false);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p3, 0);
            int i5 = c0814p3.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p3.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p3, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p3.b0();
            if (c0814p3.O) {
                c0814p3.k(c0913i);
            } else {
                c0814p3.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p3, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p3, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p3.O || !Intrinsics.b(c0814p3.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p3, i5, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p3, qVarC, c0912h4);
            boolean zBooleanValue = ((Boolean) interfaceC0773a02.getValue()).booleanValue();
            c0814p3.X(-2012597355);
            Object objI7 = c0814p3.I();
            Object obj5 = objI7;
            if (objI7 == v) {
                com.quizlet.features.practicetest.detail.composables.f fVar2 = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a02, 16);
                c0814p3.i0(fVar2);
                obj5 = fVar2;
            }
            c0814p3.p(false);
            androidx.work.impl.t.a(zBooleanValue, (Function0) obj5, c0814p3, 48, 0);
            Long l = (Long) interfaceC0773a0.getValue();
            if (l != null) {
                long jLongValue = l.longValue();
                String format = DateFormat.getBestDateTimePattern(Locale.getDefault(), "yyyy/MM/dd");
                Intrinsics.checkNotNullExpressionValue(format, "getBestDateTimePattern(...)");
                bVar2.getClass();
                Intrinsics.checkNotNullParameter(format, "format");
                Calendar calendarB = com.quizlet.time.b.b();
                calendarB.setTimeZone(TimeZone.getTimeZone(ZoneId.of("UTC")));
                calendarB.setTimeInMillis(jLongValue);
                Calendar calendarB2 = com.quizlet.time.b.b();
                calendarB2.set(calendarB.get(1), calendarB.get(2), calendarB.get(5), 0, 0, 0);
                calendarB2.setTimeZone(TimeZone.getDefault());
                str = new SimpleDateFormat(format, Locale.getDefault()).format(Long.valueOf(calendarB2.getTimeInMillis()));
                Intrinsics.checkNotNullExpressionValue(str, "format(...)");
            } else {
                str = null;
            }
            if (str == null) {
                str = "";
            }
            AbstractC3745v5.a(str, null, null, AbstractC3106b5.d(c0814p3, R.string.signup_birthday_input_label), null, 0, 0, null, null, 0, 0, null, null, false, true, null, 0, null, DefinitionKt.NO_Float_VALUE, null, lVar, com.quizlet.login.common.ui.g.a, c0814p3, 0, 196608, 384, 2064374);
            C0814p c0814p4 = c0814p3;
            c0814p4.X(-2012581596);
            if (((Boolean) interfaceC0773a02.getValue()).booleanValue()) {
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
                int i6 = c0814p4.P;
                InterfaceC0803j0 interfaceC0803j0L2 = c0814p4.l();
                androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p4, nVar);
                c0814p4.b0();
                if (c0814p4.O) {
                    c0814p4.k(c0913i);
                } else {
                    c0814p4.l0();
                }
                C0776c.E(c0814p4, kE, c0912h);
                C0776c.E(c0814p4, interfaceC0803j0L2, c0912h2);
                if (c0814p4.O || !Intrinsics.b(c0814p4.I(), Integer.valueOf(i6))) {
                    android.support.v4.media.session.a.z(i6, c0814p4, i6, c0912h3);
                }
                C0776c.E(c0814p4, qVarC2, c0912h4);
                c0814p4.X(164256084);
                Object objI8 = c0814p4.I();
                Object obj6 = objI8;
                if (objI8 == v) {
                    com.quizlet.features.practicetest.detail.composables.f fVar3 = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a02, 17);
                    c0814p4.i0(fVar3);
                    obj6 = fVar3;
                }
                Function0 function0 = (Function0) obj6;
                c0814p4.p(false);
                Set set = androidx.compose.material3.windowsizeclass.c.b;
                int i7 = bVar6.a;
                z = true;
                androidx.compose.ui.window.l.b(null, 0L, function0, new androidx.compose.ui.window.y(false, true, true, 1, true, !(i7 == 0)), androidx.compose.runtime.internal.e.e(1410465819, new com.quizlet.features.flashcards.settings.ui.h(i7, c0585a1, true ? 1 : 0), c0814p4), c0814p4, 24960, 3);
                C0814p c0814p5 = c0814p4;
                c0814p5.p(true);
                c0814p = c0814p5;
            } else {
                z = true;
                c0814p = c0814p4;
            }
            c0814p.p(false);
            c0814p.p(z);
            bVar5 = bVar2;
            c0814p2 = c0814p;
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.login.common.ui.a(function1, calendarData, qVar, bVar5, i, 0);
        }
    }

    public static final void b(androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1547183463);
        if (((i | 6) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            AbstractC4827u.a(AbstractC3106b5.d(c0814p, R.string.signup_birthdate_tooltip), nVar2, null, null, false, 0, com.quizlet.login.common.ui.g.c, null, c0814p, 1572912, 188);
            nVar = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.changetags.composables.a(nVar, i, 5);
        }
    }

    public static int c(com.iabtcf.utils.a aVar, int i) {
        int iD = aVar.d(i);
        int iA = com.iabtcf.utils.l.K.a(aVar) + i;
        for (int i2 = 0; i2 < iD; i2++) {
            iA += com.iabtcf.utils.l.M.a(aVar) + com.iabtcf.utils.l.L.a(aVar) + (aVar.b(iA) ? com.iabtcf.utils.l.V.a(aVar) : 0);
        }
        return iA - i;
    }
}
