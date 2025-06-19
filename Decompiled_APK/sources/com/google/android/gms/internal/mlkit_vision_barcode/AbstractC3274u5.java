package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3274u5;
import com.quizlet.quizletandroid.R;
import com.quizlet.ui.compose.C4828v;
import com.quizlet.ui.compose.C4830x;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.u5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3274u5 {
    public static final void a(float f, boolean z, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1772742780);
        if ((i & 6) == 0) {
            i2 = (c0814p.c(f) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            d(f, c0814p, i2 & 14);
            c0814p.X(-1952776445);
            if (z) {
                b(c0814p, 0);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4828v(f, z, qVar, i, 0);
        }
    }

    public static final void b(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-2137303966);
        if (i == 0 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, R.string.for_teachers_logo_subtitle), null, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).o(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.b)).n, c0814p, 0, 0, 65530);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4830x(i);
        }
    }

    public static final void c(float f, boolean z, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(867768148);
        if ((i & 6) == 0) {
            i2 = (c0814p.c(f) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(-757110087);
            if (z) {
                b(c0814p, 0);
            }
            c0814p.p(false);
            d(f, c0814p, i2 & 14);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4828v(f, z, qVar, i, 1);
        }
    }

    public static final void d(final float f, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1428650217);
        if ((i & 6) == 0) {
            i2 = (c0814p.c(f) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC0460p.c(Z4.a(2131231620, c0814p, 0), AbstractC3106b5.d(c0814p, R.string.quizlet_plus), androidx.compose.foundation.layout.K0.d(androidx.compose.ui.n.b, f), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 0, 120);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.ui.compose.w
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).intValue();
                    int iH = C0776c.H(i | 1);
                    AbstractC3274u5.d(f, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void e(androidx.compose.ui.q qVar, com.quizlet.ui.states.a aVar, float f, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1838162510);
        int i4 = i2 & 1;
        if (i4 != 0) {
            i3 = i | 6;
        } else {
            i3 = (c0814p.f(qVar) ? 4 : 2) | i;
        }
        int i5 = i3 | (c0814p.f(aVar) ? 32 : 16) | 128;
        if ((i5 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                if (i4 != 0) {
                    qVar = androidx.compose.ui.n.b;
                }
                com.quizlet.themes.m.g.h();
                f = com.quizlet.ui.resources.designsystem.generated.h.g;
            } else {
                c0814p.Q();
            }
            int i6 = i5 & (-897);
            c0814p.q();
            boolean z = ((Context) c0814p.j(AndroidCompositionLocals_androidKt.b)).getResources().getBoolean(R.bool.invert_teacher_logo_subtitle);
            boolean z2 = aVar == com.quizlet.ui.states.a.d;
            if (z) {
                c0814p.X(-1751655429);
                c(f, z2, qVar, c0814p, (i6 << 6) & 896);
                c0814p.p(false);
            } else {
                c0814p.X(-1751557252);
                a(f, z2, qVar, c0814p, (i6 << 6) & 896);
                c0814p.p(false);
            }
        }
        androidx.compose.ui.q qVar2 = qVar;
        float f2 = f;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.a(qVar2, aVar, f2, i, i2);
        }
    }

    public static final com.quizlet.qutils.string.g f(com.quizlet.qutils.language.e eVar) {
        Intrinsics.checkNotNullParameter(eVar, "<this>");
        if (Intrinsics.b(eVar, com.quizlet.qutils.language.d.a)) {
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            return new com.quizlet.qutils.string.f(R.string.term, C4933y.P(args));
        }
        if (Intrinsics.b(eVar, com.quizlet.qutils.language.b.a)) {
            Object[] args2 = new Object[0];
            Intrinsics.checkNotNullParameter(args2, "args");
            return new com.quizlet.qutils.string.f(R.string.definition, C4933y.P(args2));
        }
        if (!(eVar instanceof com.quizlet.qutils.language.c)) {
            throw new NoWhenBranchMatchedException();
        }
        String string = ((com.quizlet.qutils.language.c) eVar).a;
        Intrinsics.checkNotNullParameter(string, "string");
        return new com.quizlet.qutils.string.e(string);
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x002b  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x003a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object g(int r7, java.lang.Object r8, androidx.compose.ui.text.font.A r9, androidx.compose.ui.text.font.u r10, int r11) {
        /*
            boolean r0 = r8 instanceof android.graphics.Typeface
            if (r0 != 0) goto L5
            return r8
        L5:
            r0 = 2
            r1 = 1
            r2 = 0
            if (r7 != r1) goto Lb
            goto Ld
        Lb:
            if (r7 != r0) goto L2b
        Ld:
            androidx.compose.ui.text.font.u r3 = r9.b
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r3, r10)
            if (r3 != 0) goto L2b
            androidx.compose.ui.text.font.u r3 = androidx.compose.ui.text.font.u.d
            int r4 = r10.compareTo(r3)
            if (r4 < 0) goto L2b
            androidx.compose.ui.text.font.u r4 = r9.b
            int r4 = r4.a
            int r3 = r3.a
            int r3 = kotlin.jvm.internal.Intrinsics.g(r4, r3)
            if (r3 >= 0) goto L2b
            r3 = r1
            goto L2c
        L2b:
            r3 = r2
        L2c:
            r4 = 3
            if (r7 != r1) goto L30
            goto L32
        L30:
            if (r7 != r4) goto L3a
        L32:
            r9.getClass()
            if (r11 != 0) goto L38
            goto L3a
        L38:
            r7 = r1
            goto L3b
        L3a:
            r7 = r2
        L3b:
            if (r7 != 0) goto L40
            if (r3 != 0) goto L40
            return r8
        L40:
            int r5 = android.os.Build.VERSION.SDK_INT
            r6 = 28
            if (r5 >= r6) goto L62
            if (r7 == 0) goto L4c
            if (r11 != r1) goto L4c
            r7 = r1
            goto L4d
        L4c:
            r7 = r2
        L4d:
            if (r7 == 0) goto L53
            if (r3 == 0) goto L53
            r0 = r4
            goto L5b
        L53:
            if (r3 == 0) goto L57
            r0 = r1
            goto L5b
        L57:
            if (r7 == 0) goto L5a
            goto L5b
        L5a:
            r0 = r2
        L5b:
            android.graphics.Typeface r8 = (android.graphics.Typeface) r8
            android.graphics.Typeface r7 = android.graphics.Typeface.create(r8, r0)
            return r7
        L62:
            if (r3 == 0) goto L67
            int r10 = r10.a
            goto L6b
        L67:
            androidx.compose.ui.text.font.u r10 = r9.b
            int r10 = r10.a
        L6b:
            if (r7 == 0) goto L73
            if (r11 != r1) goto L70
            goto L71
        L70:
            r1 = r2
        L71:
            r2 = r1
            goto L76
        L73:
            r9.getClass()
        L76:
            androidx.compose.ui.text.font.D r7 = androidx.compose.ui.text.font.D.a
            android.graphics.Typeface r8 = (android.graphics.Typeface) r8
            android.graphics.Typeface r7 = r7.a(r8, r10, r2)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3274u5.g(int, java.lang.Object, androidx.compose.ui.text.font.A, androidx.compose.ui.text.font.u, int):java.lang.Object");
    }
}
