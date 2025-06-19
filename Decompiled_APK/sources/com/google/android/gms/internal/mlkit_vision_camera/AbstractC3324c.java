package com.google.android.gms.internal.mlkit_vision_camera;

import android.content.res.Resources;
import androidx.compose.material3.A4;
import androidx.compose.material3.D4;
import androidx.compose.material3.K4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3169i5;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.AbstractC4921l;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3324c {
    public static final void a(String text, Function1 onTextChange, androidx.compose.ui.q qVar, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(onTextChange, "onTextChange");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-2128820132);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(text) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(onTextChange) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.g(z) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.X(654008640);
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = new androidx.compose.ui.focus.p();
                c0814p2.i0(objI);
            }
            androidx.compose.ui.focus.p pVar = (androidx.compose.ui.focus.p) objI;
            c0814p2.p(false);
            androidx.compose.ui.text.L l = AbstractC3169i5.g(c0814p2).o;
            com.quizlet.themes.m.g.c();
            androidx.compose.foundation.shape.d dVarA = androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.h);
            D4 d4 = D4.a;
            int i3 = i2;
            A4 a4C = D4.c(AbstractC3169i5.f(c0814p2).b.e(), AbstractC3169i5.f(c0814p2).b.e(), AbstractC3169i5.f(c0814p2).b.e(), 0L, AbstractC3169i5.f(c0814p2).A(), AbstractC3169i5.f(c0814p2).A(), AbstractC3169i5.f(c0814p2).A(), AbstractC3169i5.f(c0814p2).A(), 0L, 0L, null, AbstractC3169i5.f(c0814p2).A(), AbstractC3169i5.f(c0814p2).A(), 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, c0814p2, 2147477256);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.ui.focus.a.k(qVar.g(androidx.compose.foundation.layout.K0.c), pVar), "TextFieldView");
            c0814p2.X(654052641);
            int i4 = i3 & 14;
            boolean z2 = i4 == 4;
            Object objI2 = c0814p2.I();
            if (z2 || objI2 == v) {
                objI2 = new com.quizlet.features.notes.upload.composables.common.e();
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            K4.b(text, onTextChange, androidx.compose.ui.input.key.c.d(qVarG, (Function1) objI2), false, false, l, null, com.quizlet.features.notes.upload.composables.common.b.a, null, null, null, false, null, null, null, false, 0, 0, null, dVarA, a4C, c0814p2, i4 | 12582912 | (i3 & ContentType.LONG_FORM_ON_DEMAND), 0, 0, 2096984);
            c0814p = c0814p2;
            if (z) {
                Unit unit = Unit.a;
                c0814p.X(654059544);
                Object objI3 = c0814p.I();
                if (objI3 == v) {
                    objI3 = new com.quizlet.features.notes.upload.composables.common.f(pVar, null);
                    c0814p.i0(objI3);
                }
                c0814p.p(false);
                C0776c.f(c0814p, unit, (Function2) objI3);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.recyclerview.step.g(text, onTextChange, qVar, z, i, 4);
        }
    }

    public static final boolean b(Object[] objArr, int i, int i2, List list) {
        if (i2 == list.size()) {
            for (int i3 = 0; i3 < i2; i3++) {
                if (Intrinsics.b(objArr[i + i3], list.get(i3))) {
                }
            }
            return true;
        }
        return false;
    }

    public static final String c(Object[] objArr, int i, int i2, AbstractC4921l abstractC4921l) {
        StringBuilder sb = new StringBuilder((i2 * 3) + 2);
        sb.append("[");
        for (int i3 = 0; i3 < i2; i3++) {
            if (i3 > 0) {
                sb.append(", ");
            }
            Object obj = objArr[i + i3];
            if (obj == abstractC4921l) {
                sb.append("(this Collection)");
            } else {
                sb.append(obj);
            }
        }
        sb.append("]");
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    public static final float d(List list, Resources resources) {
        float dimension = 0;
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            dimension += resources.getDimension(((Number) it2.next()).intValue()) / resources.getDisplayMetrics().density;
        }
        return dimension;
    }

    public static final androidx.glance.p e(androidx.glance.p pVar, float f) {
        androidx.glance.layout.n nVarH = h(f);
        return pVar.d(new androidx.glance.layout.o(nVarH, nVarH, nVarH, nVarH));
    }

    public static androidx.glance.p f(androidx.glance.p pVar, float f, float f2, float f3, float f4, int i) {
        if ((i & 1) != 0) {
            f = 0;
        }
        if ((i & 2) != 0) {
            f2 = 0;
        }
        if ((i & 4) != 0) {
            f3 = 0;
        }
        if ((i & 8) != 0) {
            f4 = 0;
        }
        return pVar.d(new androidx.glance.layout.o(h(f), h(f2), h(f3), h(f4)));
    }

    public static final void g(int i, int i2, Object[] objArr) {
        Intrinsics.checkNotNullParameter(objArr, "<this>");
        while (i < i2) {
            Intrinsics.checkNotNullParameter(objArr, "<this>");
            objArr[i] = null;
            i++;
        }
    }

    public static final androidx.glance.layout.n h(float f) {
        return new androidx.glance.layout.n(f, 2);
    }
}
