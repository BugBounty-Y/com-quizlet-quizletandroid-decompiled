package androidx.compose.ui.viewinterop;

import android.content.Context;
import android.graphics.Rect;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import androidx.compose.animation.U;
import androidx.compose.foundation.gestures.C0346q0;
import androidx.compose.foundation.layout.C0419y;
import androidx.compose.foundation.text.selection.n0;
import androidx.compose.runtime.C0775b0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0810n;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.focus.t;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.C0923t;
import androidx.compose.ui.node.E;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.compose.ui.q;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentContainerView;
import androidx.lifecycle.J;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3144f7;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class k {
    public static final j a = new j();

    public static final void a(Function1 function1, q qVar, Function1 function12, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        Function1 function13;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1783766393);
        if ((i & 6) == 0) {
            i3 = (c0814p.h(function1) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p.f(qVar) ? 32 : 16;
        }
        int i4 = i2 & 4;
        if (i4 != 0) {
            i3 |= 384;
        } else if ((i & 384) == 0) {
            i3 |= c0814p.h(function12) ? 256 : 128;
        }
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            function13 = function12;
        } else {
            a aVar = a.f;
            Function1 function14 = i4 != 0 ? aVar : function12;
            b(function1, qVar, null, aVar, function14, c0814p, (i3 & 14) | 3072 | (i3 & ContentType.LONG_FORM_ON_DEMAND) | ((i3 << 6) & 57344), 4);
            function13 = function14;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0419y(function1, qVar, function13, i, i2, 4);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x004f  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0054  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0087  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0096  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0098  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x009d  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00ef  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x012f  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0171  */
    /* JADX WARN: Removed duplicated region for block: B:92:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(kotlin.jvm.functions.Function1 r18, androidx.compose.ui.q r19, kotlin.jvm.functions.Function1 r20, kotlin.jvm.functions.Function1 r21, kotlin.jvm.functions.Function1 r22, androidx.compose.runtime.InterfaceC0806l r23, int r24, int r25) {
        /*
            Method dump skipped, instructions count: 383
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.viewinterop.k.b(kotlin.jvm.functions.Function1, androidx.compose.ui.q, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    public static final void c(kotlin.jvm.functions.c cVar, q qVar, a aVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        a aVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(509101952);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(cVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(null) ? 256 : 128;
        }
        int i3 = i2 | 3072;
        if ((i & 24576) == 0) {
            i3 |= c0814p.h(function1) ? 16384 : 8192;
        }
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            aVar2 = aVar;
        } else {
            aVar2 = a.b;
            View view = (View) c0814p.j(AndroidCompositionLocals_androidKt.f);
            boolean zF = c0814p.f(view);
            Object objI = c0814p.I();
            V v = C0804k.a;
            if (zF || objI == v) {
                try {
                    objI = AbstractC3144f7.b(view);
                } catch (IllegalStateException unused) {
                    objI = null;
                }
                c0814p.i0(objI);
            }
            Fragment fragment = (Fragment) objI;
            Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
            boolean zH = ((i3 & 14) == 4) | c0814p.h(fragment);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                objI2 = new n0(29, fragment, cVar);
                c0814p.i0(objI2);
            }
            Function1 function12 = (Function1) objI2;
            c0814p.X(1526457000);
            c0814p.p(false);
            boolean zH2 = ((i3 & 7168) == 2048) | c0814p.h(fragment) | c0814p.h(context);
            Object objI3 = c0814p.I();
            if (zH2 || objI3 == v) {
                objI3 = new b(0, fragment, context);
                c0814p.i0(objI3);
            }
            Function1 function13 = (Function1) objI3;
            boolean z = (57344 & i3) == 16384;
            Object objI4 = c0814p.I();
            if (z || objI4 == v) {
                objI4 = new U(4, function1);
                c0814p.i0(objI4);
            }
            b(function12, qVar, null, function13, (Function1) objI4, c0814p, i3 & ContentType.LONG_FORM_ON_DEMAND, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.b(cVar, qVar, aVar2, function1, i);
        }
    }

    public static final void d(kotlin.jvm.functions.c cVar, q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1985291610);
        int i2 = (c0814p.h(function1) ? 256 : 128) | i;
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c(cVar, qVar, null, function1, c0814p, 438 | ((i2 << 6) & 57344));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0346q0(i, 9, cVar, qVar, function1);
        }
    }

    public static final boolean e(View view, View view2) {
        for (ViewParent parent = view2.getParent(); parent != null; parent = parent.getParent()) {
            if (parent == view.getParent()) {
                return true;
            }
        }
        return false;
    }

    public static final Rect f(androidx.compose.ui.focus.h hVar, View view, View view2) {
        int[] iArr = new int[2];
        view.getLocationOnScreen(iArr);
        int[] iArr2 = new int[2];
        view2.getLocationOnScreen(iArr2);
        t tVarG = androidx.compose.ui.focus.a.g(((androidx.compose.ui.focus.j) hVar).f);
        androidx.compose.ui.geometry.c cVarJ = tVarG != null ? androidx.compose.ui.focus.a.j(tVarG) : null;
        if (cVarJ == null) {
            return null;
        }
        int i = (int) cVarJ.a;
        int i2 = iArr[0];
        int i3 = iArr2[0];
        int i4 = (int) cVarJ.b;
        int i5 = iArr[1];
        int i6 = iArr2[1];
        return new Rect((i + i2) - i3, (i4 + i5) - i6, (((int) cVarJ.c) + i2) - i3, (((int) cVarJ.d) + i5) - i6);
    }

    public static final View g(androidx.compose.ui.p pVar) {
        p pVar2 = AbstractC0910f.v(pVar.a).j;
        View interopView = pVar2 != null ? pVar2.getInteropView() : null;
        if (interopView != null) {
            return interopView;
        }
        throw new IllegalStateException("Could not fetch interop view");
    }

    public static final void h(p pVar, E e) {
        long jU = ((C0923t) e.w.c).U(0L);
        int iRound = Math.round(androidx.compose.ui.geometry.b.d(jU));
        int iRound2 = Math.round(androidx.compose.ui.geometry.b.e(jU));
        pVar.layout(iRound, iRound2, pVar.getMeasuredWidth() + iRound, pVar.getMeasuredHeight() + iRound2);
    }

    public static final p i(E e) {
        p pVar = e.j;
        if (pVar != null) {
            return pVar;
        }
        W4.g("Required value was null.");
        throw null;
    }

    public static final Function0 j(Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        int i2 = c0814p.P;
        Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
        C0810n c0810nC = C0776c.C(c0814p);
        androidx.compose.runtime.saveable.i iVar = (androidx.compose.runtime.saveable.i) c0814p.j(androidx.compose.runtime.saveable.k.a);
        View view = (View) c0814p.j(AndroidCompositionLocals_androidKt.f);
        boolean zH = ((((i & 14) ^ 6) > 4 && c0814p.f(function1)) || (i & 6) == 4) | c0814p.h(context) | c0814p.h(c0810nC) | c0814p.h(iVar) | c0814p.d(i2) | c0814p.h(view);
        Object objI = c0814p.I();
        if (zH || objI == C0804k.a) {
            objI = new m(context, function1, c0810nC, iVar, i2, view);
            c0814p.i0(objI);
        }
        return (Function0) objI;
    }

    public static final void k(ViewGroup viewGroup, C0775b0 c0775b0) {
        if (viewGroup instanceof FragmentContainerView) {
            c0775b0.invoke(viewGroup);
            return;
        }
        int childCount = viewGroup.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = viewGroup.getChildAt(i);
            Intrinsics.c(childAt, "getChildAt(index)");
            if (childAt instanceof ViewGroup) {
                k((ViewGroup) childAt, c0775b0);
            }
        }
    }

    public static final void l(InterfaceC0806l interfaceC0806l, q qVar, int i, androidx.compose.ui.unit.b bVar, J j, androidx.savedstate.f fVar, androidx.compose.ui.unit.k kVar, InterfaceC0803j0 interfaceC0803j0) {
        InterfaceC0915k.D0.getClass();
        C0776c.E(interfaceC0806l, interfaceC0803j0, C0914j.e);
        C0776c.E(interfaceC0806l, qVar, l.g);
        C0776c.E(interfaceC0806l, bVar, l.h);
        C0776c.E(interfaceC0806l, j, l.i);
        C0776c.E(interfaceC0806l, fVar, l.j);
        C0776c.E(interfaceC0806l, kVar, l.k);
        C0912h c0912h = C0914j.g;
        C0814p c0814p = (C0814p) interfaceC0806l;
        if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i))) {
            android.support.v4.media.session.a.z(i, c0814p, i, c0912h);
        }
    }
}
