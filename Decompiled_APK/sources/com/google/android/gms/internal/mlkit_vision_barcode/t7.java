package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
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
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.glance.appwidget.C1177j0;
import androidx.glance.appwidget.C1217u;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3673m4;
import com.quizlet.data.model.EnumC4175w;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.AbstractC4388g;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4392k;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.EOFException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;

/* loaded from: classes2.dex */
public abstract class t7 {
    public static final void a(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1257244356);
        if (i == 0 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i2 = C1177j0.a;
            c0814p.Y(-1115894518);
            c0814p.Y(1886828752);
            if (!(c0814p.a instanceof androidx.glance.b)) {
                C0776c.s();
                throw null;
            }
            c0814p.V();
            if (c0814p.O) {
                c0814p.k(new C1217u(0, 1));
            } else {
                c0814p.l0();
            }
            androidx.compose.ui.node.B.s(c0814p, true, false, false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.glance.appwidget.q0(i);
        }
    }

    public static final void b(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        float f;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2119602139);
        if ((((c0814p.f(qVar) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(894059059);
            for (int i3 = 0; i3 < 3; i3++) {
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                if (i3 == 0) {
                    mVar.q();
                    f = com.quizlet.ui.resources.designsystem.generated.j.i;
                } else {
                    mVar.s();
                    f = com.quizlet.ui.resources.designsystem.generated.j.h;
                }
                S5.d(f, androidx.compose.foundation.layout.K0.c(androidx.compose.ui.n.b, 1.0f), null, c0814p, 48);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 9, qVar);
        }
    }

    public static final void c(String str, EnumC4175w enumC4175w, androidx.compose.ui.q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        androidx.compose.ui.q qVar2;
        int i4;
        Function0 function02;
        int i5;
        Function0 function03;
        Function0 function04;
        boolean z;
        androidx.compose.ui.q qVar3;
        Function0 function05;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1565289515);
        if ((i & 6) == 0) {
            i3 = i | (c0814p.f(str) ? 4 : 2);
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p.f(enumC4175w) ? 32 : 16;
        }
        int i6 = i2 & 4;
        if (i6 != 0) {
            i4 = i3 | 384;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i4 = i3 | (c0814p.f(qVar2) ? 256 : 128);
        }
        int i7 = i2 & 8;
        if (i7 != 0) {
            i5 = i4 | 3072;
            function02 = function0;
        } else {
            function02 = function0;
            i5 = i4 | (c0814p.h(function02) ? 2048 : 1024);
        }
        if ((i5 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            qVar3 = qVar2;
            function05 = function02;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVar4 = i6 != 0 ? nVar : qVar2;
            androidx.compose.runtime.V v = C0804k.a;
            if (i7 != 0) {
                c0814p.X(683548444);
                Object objI = c0814p.I();
                if (objI == v) {
                    objI = new C4392k(7);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                function03 = (Function0) objI;
            } else {
                function03 = function02;
            }
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i8 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar4);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            Object[] objArr = new Object[0];
            c0814p.X(-1138080334);
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new C4392k(8);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI2, c0814p, 3072, 6);
            int i9 = enumC4175w == null ? -1 : com.quizlet.features.notes.detail.composables.magicnotesdetail.M.a[enumC4175w.ordinal()];
            if (i9 == 1) {
                function04 = function03;
                z = true;
                c0814p.X(-920636540);
                if (str == null || str.length() == 0) {
                    c0814p.X(-920600983);
                    AbstractC3144f7.a(null, c0814p, 0);
                    c0814p.p(false);
                } else {
                    c0814p.X(-920517810);
                    androidx.compose.runtime.X0 x0 = AndroidCompositionLocals_androidKt.b;
                    AbstractC3673m4.a(new com.quizlet.qatex.c(str, com.quizlet.themes.extensions.a.a((Context) c0814p.j(x0), R.attr.SysColorTextPrimary), AbstractC3187k5.c((Context) c0814p.j(x0), R.style.Body_B4), false), null, false, null, null, c0814p, 0, 30);
                    c0814p = c0814p;
                    c0814p.p(false);
                }
                c0814p.p(false);
            } else if (i9 != 2) {
                c0814p.X(-1138026236);
                com.quizlet.themes.m.g.p();
                AbstractC3180j7.a(0, 0, c0814p, androidx.compose.ui.platform.N.G(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, 7), "quickReferenceError"));
                c0814p.p(false);
                z = true;
                function04 = function03;
            } else {
                c0814p.X(-919949704);
                z = true;
                function04 = function03;
                androidx.compose.animation.E.f(((Boolean) interfaceC0773a0.getValue()).booleanValue(), null, null, null, null, AbstractC4388g.a, c0814p, 1572870, 30);
                androidx.compose.animation.E.f(!((Boolean) interfaceC0773a0.getValue()).booleanValue(), null, null, null, null, androidx.compose.runtime.internal.e.e(-1596784017, new com.quizlet.assembly.compose.input.g(interfaceC0773a0, function04, 4), c0814p), c0814p, 1572870, 30);
                c0814p.p(false);
            }
            c0814p.p(z);
            qVar3 = qVar4;
            function05 = function04;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.K(str, enumC4175w, qVar3, function05, i, i2, 1);
        }
    }

    public static final String d(CharsetDecoder charsetDecoder, kotlinx.io.i input) throws EOFException {
        Intrinsics.checkNotNullParameter(charsetDecoder, "<this>");
        Intrinsics.checkNotNullParameter(input, "input");
        StringBuilder dst = new StringBuilder((int) Math.min(SubsamplingScaleImageView.TILE_SIZE_AUTO, input.c().c));
        Intrinsics.checkNotNullParameter(charsetDecoder, "<this>");
        Intrinsics.checkNotNullParameter(input, "input");
        Intrinsics.checkNotNullParameter(dst, "dst");
        Intrinsics.checkNotNullParameter(charsetDecoder, "<this>");
        Charset charset = charsetDecoder.charset();
        Intrinsics.d(charset);
        if (charset.equals(Charsets.UTF_8)) {
            dst.append((CharSequence) kotlinx.io.j.f(input));
        } else {
            u7.c(input);
            Intrinsics.checkNotNullParameter(input, "<this>");
            Intrinsics.checkNotNullParameter(input, "<this>");
            byte[] byteArray = kotlinx.io.j.e(input, -1);
            Intrinsics.checkNotNullParameter(byteArray, "array");
            char[] cArr = kotlinx.io.bytestring.a.c;
            Intrinsics.checkNotNullParameter(byteArray, "byteArray");
            kotlinx.io.bytestring.a aVar = new kotlinx.io.bytestring.a(byteArray);
            Intrinsics.checkNotNullParameter(charsetDecoder, "<this>");
            Charset charset2 = charsetDecoder.charset();
            Intrinsics.d(charset2);
            Intrinsics.checkNotNullParameter(aVar, "<this>");
            Intrinsics.checkNotNullParameter(charset2, "charset");
            dst.append((CharSequence) new String(byteArray, charset2));
        }
        String string = dst.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    public static final boolean e(androidx.glance.k kVar) {
        if (kVar instanceof androidx.glance.appwidget.C) {
            return true;
        }
        if (!(kVar instanceof androidx.glance.m)) {
            return false;
        }
        ArrayList arrayList = ((androidx.glance.m) kVar).c;
        if (arrayList != null && arrayList.isEmpty()) {
            return false;
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            if (e((androidx.glance.k) it2.next())) {
                return true;
            }
        }
        return false;
    }
}
