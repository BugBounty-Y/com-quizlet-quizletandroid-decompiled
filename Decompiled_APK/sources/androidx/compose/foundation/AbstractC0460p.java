package androidx.compose.foundation;

import android.content.Context;
import android.content.res.Configuration;
import androidx.compose.foundation.gestures.AbstractC0349s0;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.gestures.InterfaceC0314a0;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.vector.AbstractC0863b;
import androidx.compose.ui.graphics.vector.C0867f;
import androidx.compose.ui.layout.C0888i;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.google.android.gms.internal.mlkit_vision_barcode.O4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0460p {
    public static final C0555x a(long j, float f) {
        return new C0555x(f, new androidx.compose.ui.graphics.X(j));
    }

    public static final void b(androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-932836462);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC0382e.f(c0814p, androidx.compose.ui.draw.g.e(qVar, function1));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0556y(qVar, function1, i);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:103:0x011f  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0151  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x0155  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x017b  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x018d  */
    /* JADX WARN: Removed duplicated region for block: B:118:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x004f  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0054  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0087  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x008b  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00a2  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00c4  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x00d5  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00d9  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x00dc  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x00e1  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x00f3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(androidx.compose.ui.graphics.painter.b r17, java.lang.String r18, androidx.compose.ui.q r19, androidx.compose.ui.i r20, androidx.compose.ui.layout.InterfaceC0889j r21, float r22, androidx.compose.ui.graphics.AbstractC0874w r23, androidx.compose.runtime.InterfaceC0806l r24, int r25, int r26) {
        /*
            Method dump skipped, instructions count: 409
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.AbstractC0460p.c(androidx.compose.ui.graphics.painter.b, java.lang.String, androidx.compose.ui.q, androidx.compose.ui.i, androidx.compose.ui.layout.j, float, androidx.compose.ui.graphics.w, androidx.compose.runtime.l, int, int):void");
    }

    public static final void d(C0867f c0867f, String str, androidx.compose.ui.q qVar, C0853m c0853m, InterfaceC0806l interfaceC0806l, int i, int i2) {
        if ((i2 & 4) != 0) {
            qVar = androidx.compose.ui.n.b;
        }
        androidx.compose.ui.i iVar = androidx.compose.ui.b.e;
        androidx.compose.ui.layout.P p = C0888i.b;
        c(AbstractC0863b.c(c0867f, interfaceC0806l), str, qVar, iVar, p, 1.0f, c0853m, interfaceC0806l, 8 | (i & ContentType.LONG_FORM_ON_DEMAND), 0);
    }

    public static androidx.compose.ui.q e(androidx.compose.ui.q qVar, androidx.compose.ui.graphics.I i, androidx.compose.foundation.shape.d dVar, int i2) {
        androidx.compose.ui.graphics.V v = dVar;
        if ((i2 & 2) != 0) {
            v = androidx.compose.ui.graphics.F.a;
        }
        return qVar.g(new BackgroundElement(0L, i, v, 1));
    }

    public static final androidx.compose.ui.q f(androidx.compose.ui.q qVar, long j, androidx.compose.ui.graphics.V v) {
        return qVar.g(new BackgroundElement(j, null, v, 2));
    }

    public static final androidx.compose.ui.q g(androidx.compose.ui.q qVar, float f, long j, androidx.compose.ui.graphics.V v) {
        return h(qVar, f, new androidx.compose.ui.graphics.X(j), v);
    }

    public static final androidx.compose.ui.q h(androidx.compose.ui.q qVar, float f, androidx.compose.ui.graphics.X x, androidx.compose.ui.graphics.V v) {
        return qVar.g(new BorderModifierNodeElement(f, x, v));
    }

    public static final void i(long j, EnumC0320d0 enumC0320d0) {
        if (enumC0320d0 == EnumC0320d0.a) {
            if (androidx.compose.ui.unit.a.g(j) == Integer.MAX_VALUE) {
                throw new IllegalStateException("Vertically scrollable component was measured with an infinity maximum height constraints, which is disallowed. One of the common reasons is nesting layouts like LazyColumn and Column(Modifier.verticalScroll()). If you want to add a header before the list of items please add a header as a separate item() before the main items() inside the LazyColumn scope. There are could be other reasons for this to happen: your ComposeView was added into a LinearLayout with some weight, you applied Modifier.wrapContentSize(unbounded = true) or wrote a custom layout. Please try to remove the source of infinite constraints in the hierarchy above the scrolling container.");
            }
        } else if (androidx.compose.ui.unit.a.h(j) == Integer.MAX_VALUE) {
            throw new IllegalStateException("Horizontally scrollable component was measured with an infinity maximum width constraints, which is disallowed. One of the common reasons is nesting layouts like LazyRow and Row(Modifier.horizontalScroll()). If you want to add a header before the list of items please add a header as a separate item() before the main items() inside the LazyRow scope. There are could be other reasons for this to happen: your ComposeView was added into a LinearLayout with some weight, you applied Modifier.wrapContentSize(unbounded = true) or wrote a custom layout. Please try to remove the source of infinite constraints in the hierarchy above the scrolling container.");
        }
    }

    public static final androidx.compose.ui.q j(androidx.compose.ui.q qVar, androidx.compose.foundation.interaction.l lVar, InterfaceC0369j0 interfaceC0369j0, boolean z, String str, androidx.compose.ui.semantics.h hVar, Function0 function0) {
        androidx.compose.ui.q qVarG;
        if (interfaceC0369j0 instanceof InterfaceC0461p0) {
            qVarG = new ClickableElement(lVar, (InterfaceC0461p0) interfaceC0369j0, z, str, hVar, function0);
        } else if (interfaceC0369j0 == null) {
            qVarG = new ClickableElement(lVar, null, z, str, hVar, function0);
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            qVarG = lVar != null ? AbstractC0455m0.a(nVar, lVar, interfaceC0369j0).g(new ClickableElement(lVar, null, z, str, hVar, function0)) : androidx.compose.ui.a.a(nVar, new A(interfaceC0369j0, z, str, hVar, function0));
        }
        return qVar.g(qVarG);
    }

    public static /* synthetic */ androidx.compose.ui.q k(androidx.compose.ui.q qVar, androidx.compose.foundation.interaction.l lVar, InterfaceC0369j0 interfaceC0369j0, boolean z, androidx.compose.ui.semantics.h hVar, Function0 function0, int i) {
        if ((i & 4) != 0) {
            z = true;
        }
        boolean z2 = z;
        if ((i & 16) != 0) {
            hVar = null;
        }
        return j(qVar, lVar, interfaceC0369j0, z2, null, hVar, function0);
    }

    public static androidx.compose.ui.q l(androidx.compose.ui.q qVar, boolean z, String str, Function0 function0, int i) {
        if ((i & 1) != 0) {
            z = true;
        }
        if ((i & 2) != 0) {
            str = null;
        }
        return androidx.compose.ui.a.a(qVar, new C0557z(z, str, function0));
    }

    public static final androidx.compose.ui.q m(androidx.compose.ui.q qVar, androidx.compose.foundation.interaction.l lVar, InterfaceC0369j0 interfaceC0369j0, boolean z, Function0 function0, Function0 function02) {
        androidx.compose.ui.q qVarG;
        if (interfaceC0369j0 instanceof InterfaceC0461p0) {
            qVarG = new CombinedClickableElement(lVar, (InterfaceC0461p0) interfaceC0369j0, z, function02, function0);
        } else if (interfaceC0369j0 == null) {
            qVarG = new CombinedClickableElement(lVar, null, z, function02, function0);
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            qVarG = lVar != null ? AbstractC0455m0.a(nVar, lVar, interfaceC0369j0).g(new CombinedClickableElement(lVar, null, z, function02, function0)) : androidx.compose.ui.a.a(nVar, new B(interfaceC0369j0, z, function02, function0));
        }
        return qVar.g(qVarG);
    }

    public static androidx.compose.ui.q n(androidx.compose.ui.q qVar, Function0 function0, Function0 function02, int i) {
        return androidx.compose.ui.a.a(qVar, new C0557z(true, function0, function02));
    }

    public static androidx.compose.ui.q o(androidx.compose.ui.q qVar, N0 n0, androidx.compose.foundation.gestures.snapping.h hVar, int i) {
        if ((i & 4) != 0) {
            hVar = null;
        }
        return androidx.compose.ui.a.a(qVar, new I0(n0, hVar, true, false));
    }

    public static androidx.compose.ui.q p(androidx.compose.ui.q qVar, androidx.compose.foundation.interaction.l lVar) {
        return qVar.g(new HoverableElement(lVar));
    }

    public static final boolean q(InterfaceC0806l interfaceC0806l) {
        return (((Configuration) ((C0814p) interfaceC0806l).j(AndroidCompositionLocals_androidKt.a)).uiMode & 48) == 32;
    }

    public static final N0 r(InterfaceC0806l interfaceC0806l) {
        int i = 0;
        Object[] objArr = new Object[0];
        com.quizlet.data.repository.explanations.myexplanations.a aVar = N0.i;
        boolean zD = ((C0814p) interfaceC0806l).d(0);
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        if (zD || objI == C0804k.a) {
            objI = new C0373l0(i, 2);
            c0814p.i0(objI);
        }
        return (N0) L4.d(objArr, aVar, (Function0) objI, c0814p, 0, 4);
    }

    public static final androidx.compose.ui.q s(androidx.compose.ui.q qVar, androidx.compose.foundation.gestures.E0 e0, EnumC0320d0 enumC0320d0, boolean z, InterfaceC0314a0 interfaceC0314a0, androidx.compose.foundation.interaction.m mVar, androidx.compose.foundation.pager.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        C0 c0;
        androidx.compose.ui.q qVar2;
        androidx.compose.foundation.gestures.E0 e02;
        EnumC0320d0 enumC0320d02;
        InterfaceC0314a0 interfaceC0314a02;
        androidx.compose.foundation.interaction.m mVar2;
        boolean z2;
        boolean z3;
        if ((i & 64) != 0) {
            nVar = null;
        }
        androidx.compose.foundation.pager.n nVar2 = nVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
        A0 a0 = (A0) c0814p.j(B0.a);
        if (a0 != null) {
            c0814p.X(1586021609);
            boolean zF = c0814p.f(context) | c0814p.f(a0);
            Object objI = c0814p.I();
            if (zF || objI == C0804k.a) {
                objI = new C0456n(context, a0);
                c0814p.i0(objI);
            }
            c0 = (C0456n) objI;
            c0814p.p(false);
        } else {
            c0814p.X(1586120933);
            c0814p.p(false);
            c0 = z0.c;
        }
        C0 c02 = c0;
        EnumC0320d0 enumC0320d03 = EnumC0320d0.a;
        androidx.compose.ui.q qVarG = qVar.g(enumC0320d0 == enumC0320d03 ? G.c : G.b).g(c02.a());
        if (((androidx.compose.ui.unit.k) c0814p.j(AbstractC0955m0.l)) != androidx.compose.ui.unit.k.b || enumC0320d0 == enumC0320d03) {
            qVar2 = qVarG;
            e02 = e0;
            enumC0320d02 = enumC0320d0;
            interfaceC0314a02 = interfaceC0314a0;
            mVar2 = mVar;
            z2 = true;
            z3 = z;
        } else {
            qVar2 = qVarG;
            e02 = e0;
            z3 = z;
            interfaceC0314a02 = interfaceC0314a0;
            mVar2 = mVar;
            z2 = false;
            enumC0320d02 = enumC0320d0;
        }
        return AbstractC0349s0.e(qVar2, e02, enumC0320d02, c02, z3, z2, interfaceC0314a02, mVar2, nVar2);
    }

    public static final long t(long j, float f) {
        return O4.a(Math.max(DefinitionKt.NO_Float_VALUE, androidx.compose.ui.geometry.a.b(j) - f), Math.max(DefinitionKt.NO_Float_VALUE, androidx.compose.ui.geometry.a.c(j) - f));
    }

    public static androidx.compose.ui.q u(androidx.compose.ui.q qVar, N0 n0, boolean z, int i) {
        if ((i & 2) != 0) {
            z = true;
        }
        return androidx.compose.ui.a.a(qVar, new I0(n0, null, z, true));
    }
}
