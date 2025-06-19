package androidx.compose.ui.viewinterop;

import android.view.View;
import android.view.ViewTreeObserver;
import androidx.compose.foundation.text.z0;
import androidx.compose.ui.focus.t;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.g0;
import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import kotlin.NoWhenBranchMatchedException;

/* loaded from: classes.dex */
public final class n extends androidx.compose.ui.p implements androidx.compose.ui.focus.n, ViewTreeObserver.OnGlobalFocusChangeListener, View.OnAttachStateChangeListener {
    public View n;

    @Override // androidx.compose.ui.p
    public final void E0() {
        k.g(this).addOnAttachStateChangeListener(this);
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        k.g(this).removeOnAttachStateChangeListener(this);
        this.n = null;
    }

    public final t M0() {
        androidx.compose.ui.p pVar = this.a;
        if (!pVar.m) {
            W4.f("visitLocalDescendants called on an unattached node");
            throw null;
        }
        if ((pVar.d & 1024) != 0) {
            boolean z = false;
            for (androidx.compose.ui.p pVar2 = pVar.f; pVar2 != null; pVar2 = pVar2.f) {
                if ((pVar2.c & 1024) != 0) {
                    androidx.compose.ui.p pVarF = pVar2;
                    androidx.compose.runtime.collection.b bVar = null;
                    while (pVarF != null) {
                        if (pVarF instanceof t) {
                            t tVar = (t) pVarF;
                            if (z) {
                                return tVar;
                            }
                            z = true;
                        } else if ((pVarF.c & 1024) != 0 && (pVarF instanceof AbstractC0918n)) {
                            int i = 0;
                            for (androidx.compose.ui.p pVar3 = ((AbstractC0918n) pVarF).o; pVar3 != null; pVar3 = pVar3.f) {
                                if ((pVar3.c & 1024) != 0) {
                                    i++;
                                    if (i == 1) {
                                        pVarF = pVar3;
                                    } else {
                                        if (bVar == null) {
                                            bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                        }
                                        if (pVarF != null) {
                                            bVar.b(pVarF);
                                            pVarF = null;
                                        }
                                        bVar.b(pVar3);
                                    }
                                }
                            }
                            if (i == 1) {
                            }
                        }
                        pVarF = AbstractC0910f.f(bVar);
                    }
                }
            }
        }
        throw new IllegalStateException("Could not find focus target of embedded view wrapper");
    }

    @Override // android.view.ViewTreeObserver.OnGlobalFocusChangeListener
    public final void onGlobalFocusChanged(View view, View view2) {
        if (AbstractC0910f.v(this).i == null) {
            return;
        }
        View viewG = k.g(this);
        androidx.compose.ui.focus.h focusOwner = ((C0971v) AbstractC0910f.w(this)).getFocusOwner();
        g0 g0VarW = AbstractC0910f.w(this);
        boolean z = (view == null || view.equals(g0VarW) || !k.e(viewG, view)) ? false : true;
        boolean z2 = (view2 == null || view2.equals(g0VarW) || !k.e(viewG, view2)) ? false : true;
        if (z && z2) {
            this.n = view2;
            return;
        }
        if (!z2) {
            if (!z) {
                this.n = null;
                return;
            }
            this.n = null;
            if (M0().N0().a()) {
                ((androidx.compose.ui.focus.j) focusOwner).b(8, false, false);
                return;
            }
            return;
        }
        this.n = view2;
        t tVarM0 = M0();
        int iOrdinal = tVarM0.N0().ordinal();
        if (iOrdinal == 0 || iOrdinal == 1 || iOrdinal == 2) {
            return;
        }
        if (iOrdinal != 3) {
            throw new NoWhenBranchMatchedException();
        }
        com.bumptech.glide.manager.p pVar = ((androidx.compose.ui.focus.j) focusOwner).h;
        try {
            if (pVar.a) {
                com.bumptech.glide.manager.p.a(pVar);
            }
            pVar.a = true;
            androidx.compose.ui.focus.a.B(tVarM0);
            com.bumptech.glide.manager.p.d(pVar);
        } catch (Throwable th) {
            com.bumptech.glide.manager.p.d(pVar);
            throw th;
        }
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewAttachedToWindow(View view) {
        view.getViewTreeObserver().addOnGlobalFocusChangeListener(this);
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewDetachedFromWindow(View view) {
        view.getViewTreeObserver().removeOnGlobalFocusChangeListener(this);
    }

    @Override // androidx.compose.ui.focus.n
    public final void z(androidx.compose.ui.focus.k kVar) {
        kVar.d(false);
        kVar.a(new z0(1, this, n.class, "onEnter", "onEnter-3ESFkO8(I)Landroidx/compose/ui/focus/FocusRequester;", 0, 3));
        kVar.c(new z0(1, this, n.class, "onExit", "onExit-3ESFkO8(I)Landroidx/compose/ui/focus/FocusRequester;", 0, 4));
    }
}
