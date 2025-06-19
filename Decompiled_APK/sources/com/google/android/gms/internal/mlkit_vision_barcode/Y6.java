package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.FillElement;
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
import com.quizlet.data.model.EnumC4175w;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class Y6 {
    public static final void a(EnumC4175w status, androidx.compose.ui.q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        int i3;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(status, "status");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1222330476);
        if (((i | (c0814p.f(status) ? 4 : 2) | 48 | (c0814p.h(function0) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p.X(1590921987);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = new com.quizlet.features.emailconfirmation.ui.composables.c(21);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            c0814p.X(-970317367);
            int i4 = status == null ? -1 : com.quizlet.features.notes.helper.a.b[status.ordinal()];
            if (i4 != 1) {
                i3 = R.string.scan_notes_artifact_error_no_refresh;
                i2 = (i4 == 2 || i4 == 3) ? -1639219108 : -1639216420;
            } else {
                i2 = -1639223591;
                i3 = R.string.scan_notes_artifact_not_ready_yet;
            }
            String strH = com.google.android.gms.measurement.internal.Z.h(c0814p, i2, i3, c0814p, false);
            c0814p.p(false);
            FillElement fillElement = androidx.compose.foundation.layout.K0.c;
            com.quizlet.themes.m.g.t();
            androidx.compose.ui.q qVarU = AbstractC0382e.u(fillElement, com.quizlet.ui.resources.designsystem.generated.j.k);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.e, androidx.compose.ui.b.n, c0814p, 54);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.animation.E.f(((Boolean) interfaceC0773a0.getValue()).booleanValue(), null, null, null, null, com.quizlet.features.notes.detail.composables.common.c.a, c0814p, 1572870, 30);
            androidx.compose.animation.E.f(!((Boolean) interfaceC0773a0.getValue()).booleanValue(), null, null, null, null, androidx.compose.runtime.internal.e.e(1877202992, new com.quizlet.assembly.compose.input.h(5, strH, interfaceC0773a0, function0, false), c0814p), c0814p, 1572870, 30);
            c0814p.p(true);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 28, status, qVar2, function0);
        }
    }

    public static Set b() {
        try {
            Object objInvoke = Class.forName("android.text.EmojiConsistency").getMethod("getEmojiConsistencySet", null).invoke(null, null);
            if (objInvoke == null) {
                return Collections.EMPTY_SET;
            }
            Set set = (Set) objInvoke;
            Iterator it2 = set.iterator();
            while (it2.hasNext()) {
                if (!(it2.next() instanceof int[])) {
                    return Collections.EMPTY_SET;
                }
            }
            return set;
        } catch (Throwable unused) {
            return Collections.EMPTY_SET;
        }
    }

    public static final void c(kotlin.k kVar, String str, int i, int i2, String str2) {
        String strD = d(i, i2, str);
        if (strD.length() == 0) {
            return;
        }
        ((ArrayList) kVar.getValue()).add(new io.ktor.http.h(strD, str2));
    }

    public static final String d(int i, int i2, String str) {
        String strSubstring = str.substring(i, i2);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        return StringsKt.g0(strSubstring).toString();
    }
}
