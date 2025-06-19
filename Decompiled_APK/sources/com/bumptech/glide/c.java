package com.bumptech.glide;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.B;
import androidx.compose.foundation.layout.K0;
import androidx.compose.foundation.text.input.internal.u;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.q;
import androidx.navigation.compose.C1280m;
import androidx.work.P;
import com.google.android.gms.internal.measurement.AbstractC3058t1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U5;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.data.model.C4114c;
import com.quizlet.features.achievements.ui.composables.C4214a;
import com.quizlet.themes.w;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class c {
    public static final void C(View view, boolean z) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(view, "view");
        Context context = view.getContext();
        Object systemService = context.getSystemService("input_method");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.view.inputmethod.InputMethodManager");
        InputMethodManager inputMethodManager = (InputMethodManager) systemService;
        if (!z) {
            view.clearFocus();
            inputMethodManager.hideSoftInputFromWindow(view.getWindowToken(), 0, null);
        } else {
            Intrinsics.checkNotNullParameter(context, "context");
            if (context.getResources().getConfiguration().keyboard != 1) {
                return;
            }
            inputMethodManager.showSoftInput(view, 1, null);
        }
    }

    public static final void D(final EditText view, final boolean z) {
        Intrinsics.checkNotNullParameter(view, "view");
        final Context context = view.getContext();
        Object systemService = context.getSystemService("input_method");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.view.inputmethod.InputMethodManager");
        final InputMethodManager inputMethodManager = (InputMethodManager) systemService;
        view.setOnTouchListener(new View.OnTouchListener() { // from class: com.quizlet.qutils.android.b
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view2, MotionEvent motionEvent) {
                view2.onTouchEvent(motionEvent);
                Context context2 = context;
                InputMethodManager inputMethodManager2 = inputMethodManager;
                boolean z2 = z;
                EditText editText = view;
                if (!z2) {
                    return inputMethodManager2.hideSoftInputFromWindow(editText.getWindowToken(), 0);
                }
                Intrinsics.checkNotNullParameter(context2, "context");
                if (context2.getResources().getConfiguration().keyboard != 1) {
                    return true;
                }
                return inputMethodManager2.showSoftInput(editText, 1);
            }
        });
        if (!z) {
            inputMethodManager.hideSoftInputFromWindow(view.getWindowToken(), 0);
            return;
        }
        Intrinsics.checkNotNullParameter(context, "context");
        if (context.getResources().getConfiguration().keyboard != 1) {
            return;
        }
        inputMethodManager.showSoftInput(view, 1);
    }

    public static final void a(x state, C4114c badge, n nVar, InterfaceC0806l interfaceC0806l, int i) {
        n nVar2;
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(badge, "badge");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-437779955);
        int i2 = (c0814p.h(state) ? 4 : 2) | i | (c0814p.h(badge) ? 32 : 16) | 384;
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            n nVar3 = n.b;
            U5.b(state, nVar3, false, null, null, null, androidx.compose.runtime.internal.e.e(862661384, new com.quizlet.assembly.compose.cards.c(badge, 10), c0814p), c0814p, (i2 & 14) | 1572920, 60);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 12, state, badge, nVar2);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v6 */
    /* JADX WARN: Type inference failed for: r3v7, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r3v8 */
    public static final void b(C4114c badge, n nVar, InterfaceC0806l interfaceC0806l, int i) {
        n nVar2;
        ?? r3;
        Intrinsics.checkNotNullParameter(badge, "badge");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1378640269);
        int i2 = (c0814p.h(badge) ? 4 : 2) | i | 48;
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            nVar2 = n.b;
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            q qVarC = K0.c(nVar2, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            q qVarW = AbstractC0382e.w(qVarC, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, 1);
            B bA = A.a(AbstractC0398m.c, gVar, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarW);
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
            C0776c.E(c0814p, qVarC2, C0914j.d);
            String str = badge.d;
            mVar.p();
            float f = com.quizlet.ui.resources.designsystem.generated.j.j;
            e(str, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, 0);
            mVar.p();
            AbstractC3058t1.a(badge, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), DefinitionKt.NO_Float_VALUE, null, c0814p, i2 & 14, 12);
            String strD = P.d(badge);
            c0814p.X(-748614062);
            if (strD == null) {
                r3 = 0;
            } else {
                mVar.p();
                r3 = 0;
                d(strD, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, 0);
            }
            c0814p.p(r3);
            mVar.s();
            c(badge.e, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, r3);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(badge, nVar2, i, 8);
        }
    }

    public static final void c(String str, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-295392797);
        int i2 = i | (c0814p2.f(str) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            Q4.b(str, qVar, 0L, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(w.b)).o, c0814p, i2 & 126, 0, 65020);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4214a(str, qVar, i, 0);
        }
    }

    public static final void d(String str, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-963345442);
        int i2 = i | (c0814p2.f(str) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            Q4.b(str, qVar, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(w.b)).j, c0814p, i2 & 126, 0, 65532);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4214a(str, qVar, i, 2);
        }
    }

    public static final void e(String str, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1896960647);
        int i2 = i | (c0814p2.f(str) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            Q4.b(str, qVar, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(w.b)).e, c0814p, i2 & 126, 0, 65532);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4214a(str, qVar, i, 1);
        }
    }

    public abstract void A(CharSequence charSequence);

    public abstract void B(CharSequence charSequence);

    public androidx.appcompat.view.b E(u uVar) {
        return null;
    }

    public boolean f() {
        return false;
    }

    public abstract boolean g();

    public abstract void h(boolean z);

    public abstract int i();

    public abstract Context j();

    public abstract void k();

    public boolean l() {
        return false;
    }

    public abstract void m();

    public void n() {
    }

    public abstract boolean o(int i, KeyEvent keyEvent);

    public boolean p(KeyEvent keyEvent) {
        return false;
    }

    public boolean q() {
        return false;
    }

    public abstract void r(boolean z);

    public abstract void s(boolean z);

    public abstract void t();

    public abstract void u(boolean z);

    public abstract void v(Drawable drawable);

    public abstract void w();

    public abstract void x();

    public abstract void y(boolean z);

    public abstract void z();
}
