package androidx.appcompat.app;

import android.R;
import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.util.TypedValue;
import android.view.ContextThemeWrapper;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.View;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import androidx.appcompat.widget.ActionBarContainer;
import androidx.appcompat.widget.ActionBarContextView;
import androidx.appcompat.widget.ActionBarOverlayLayout;
import androidx.appcompat.widget.InterfaceC0081e;
import androidx.appcompat.widget.InterfaceC0096l0;
import androidx.appcompat.widget.Toolbar;
import androidx.appcompat.widget.s1;
import androidx.appcompat.widget.x1;
import androidx.core.view.C1039b0;
import androidx.core.view.C1043d0;
import androidx.core.view.V;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class T extends com.bumptech.glide.c implements InterfaceC0081e {
    public Context a;
    public Context b;
    public ActionBarOverlayLayout c;
    public ActionBarContainer d;
    public InterfaceC0096l0 e;
    public ActionBarContextView f;
    public final View g;
    public boolean h;
    public S i;
    public S j;
    public androidx.compose.foundation.text.input.internal.u k;
    public boolean l;
    public final ArrayList m;
    public int n;
    public boolean o;
    public boolean p;
    public boolean q;
    public boolean r;
    public boolean s;
    public androidx.appcompat.view.k t;
    public boolean u;
    public boolean v;
    public final P w;
    public final P x;
    public final Q y;
    public static final AccelerateInterpolator z = new AccelerateInterpolator();
    public static final DecelerateInterpolator A = new DecelerateInterpolator();

    public T(Activity activity, boolean z2) {
        new ArrayList();
        this.m = new ArrayList();
        this.n = 0;
        this.o = true;
        this.s = true;
        this.w = new P(this, 0);
        this.x = new P(this, 1);
        this.y = new Q(this);
        View decorView = activity.getWindow().getDecorView();
        G(decorView);
        if (z2) {
            return;
        }
        this.g = decorView.findViewById(R.id.content);
    }

    @Override // com.bumptech.glide.c
    public final void A(CharSequence charSequence) {
        x1 x1Var = (x1) this.e;
        x1Var.g = true;
        x1Var.h = charSequence;
        if ((x1Var.b & 8) != 0) {
            Toolbar toolbar = x1Var.a;
            toolbar.setTitle(charSequence);
            if (x1Var.g) {
                V.q(toolbar.getRootView(), charSequence);
            }
        }
    }

    @Override // com.bumptech.glide.c
    public final void B(CharSequence charSequence) {
        x1 x1Var = (x1) this.e;
        if (x1Var.g) {
            return;
        }
        x1Var.h = charSequence;
        if ((x1Var.b & 8) != 0) {
            Toolbar toolbar = x1Var.a;
            toolbar.setTitle(charSequence);
            if (x1Var.g) {
                V.q(toolbar.getRootView(), charSequence);
            }
        }
    }

    @Override // com.bumptech.glide.c
    public final androidx.appcompat.view.b E(androidx.compose.foundation.text.input.internal.u uVar) {
        S s = this.i;
        if (s != null) {
            s.a();
        }
        this.c.setHideOnContentScrollEnabled(false);
        this.f.e();
        S s2 = new S(this, this.f.getContext(), uVar);
        androidx.appcompat.view.menu.n nVar = s2.d;
        nVar.w();
        try {
            if (!((androidx.work.impl.model.i) s2.e.b).i(s2, nVar)) {
                return null;
            }
            this.i = s2;
            s2.g();
            this.f.c(s2);
            F(true);
            return s2;
        } finally {
            nVar.v();
        }
    }

    public final void F(boolean z2) {
        C1043d0 c1043d0I;
        C1043d0 c1043d0I2;
        if (z2) {
            if (!this.r) {
                this.r = true;
                ActionBarOverlayLayout actionBarOverlayLayout = this.c;
                if (actionBarOverlayLayout != null) {
                    actionBarOverlayLayout.setShowingForActionMode(true);
                }
                J(false);
            }
        } else if (this.r) {
            this.r = false;
            ActionBarOverlayLayout actionBarOverlayLayout2 = this.c;
            if (actionBarOverlayLayout2 != null) {
                actionBarOverlayLayout2.setShowingForActionMode(false);
            }
            J(false);
        }
        if (!this.d.isLaidOut()) {
            if (z2) {
                ((x1) this.e).a.setVisibility(4);
                this.f.setVisibility(0);
                return;
            } else {
                ((x1) this.e).a.setVisibility(0);
                this.f.setVisibility(8);
                return;
            }
        }
        if (z2) {
            x1 x1Var = (x1) this.e;
            c1043d0I = V.a(x1Var.a);
            c1043d0I.a(DefinitionKt.NO_Float_VALUE);
            c1043d0I.c(100L);
            c1043d0I.d(new androidx.appcompat.view.j(x1Var, 4));
            c1043d0I2 = this.f.i(0, 200L);
        } else {
            x1 x1Var2 = (x1) this.e;
            C1043d0 c1043d0A = V.a(x1Var2.a);
            c1043d0A.a(1.0f);
            c1043d0A.c(200L);
            c1043d0A.d(new androidx.appcompat.view.j(x1Var2, 0));
            c1043d0I = this.f.i(8, 100L);
            c1043d0I2 = c1043d0A;
        }
        androidx.appcompat.view.k kVar = new androidx.appcompat.view.k();
        ArrayList arrayList = kVar.a;
        arrayList.add(c1043d0I);
        View view = (View) c1043d0I.a.get();
        long duration = view != null ? view.animate().getDuration() : 0L;
        View view2 = (View) c1043d0I2.a.get();
        if (view2 != null) {
            view2.animate().setStartDelay(duration);
        }
        arrayList.add(c1043d0I2);
        kVar.b();
    }

    public final void G(View view) {
        InterfaceC0096l0 wrapper;
        ActionBarOverlayLayout actionBarOverlayLayout = (ActionBarOverlayLayout) view.findViewById(com.quizlet.quizletandroid.R.id.decor_content_parent);
        this.c = actionBarOverlayLayout;
        if (actionBarOverlayLayout != null) {
            actionBarOverlayLayout.setActionBarVisibilityCallback(this);
        }
        KeyEvent.Callback callbackFindViewById = view.findViewById(com.quizlet.quizletandroid.R.id.action_bar);
        if (callbackFindViewById instanceof InterfaceC0096l0) {
            wrapper = (InterfaceC0096l0) callbackFindViewById;
        } else {
            if (!(callbackFindViewById instanceof Toolbar)) {
                throw new IllegalStateException("Can't make a decor toolbar out of ".concat(callbackFindViewById != null ? callbackFindViewById.getClass().getSimpleName() : "null"));
            }
            wrapper = ((Toolbar) callbackFindViewById).getWrapper();
        }
        this.e = wrapper;
        this.f = (ActionBarContextView) view.findViewById(com.quizlet.quizletandroid.R.id.action_context_bar);
        ActionBarContainer actionBarContainer = (ActionBarContainer) view.findViewById(com.quizlet.quizletandroid.R.id.action_bar_container);
        this.d = actionBarContainer;
        InterfaceC0096l0 interfaceC0096l0 = this.e;
        if (interfaceC0096l0 == null || this.f == null || actionBarContainer == null) {
            throw new IllegalStateException(T.class.getSimpleName().concat(" can only be used with a compatible window decor layout"));
        }
        Context context = ((x1) interfaceC0096l0).a.getContext();
        this.a = context;
        if ((((x1) this.e).b & 4) != 0) {
            this.h = true;
        }
        androidx.appcompat.view.a aVarA = androidx.appcompat.view.a.a(context);
        int i = aVarA.a.getApplicationInfo().targetSdkVersion;
        w();
        I(aVarA.a.getResources().getBoolean(com.quizlet.quizletandroid.R.bool.abc_action_bar_embed_tabs));
        TypedArray typedArrayObtainStyledAttributes = this.a.obtainStyledAttributes(null, androidx.appcompat.a.a, com.quizlet.quizletandroid.R.attr.actionBarStyle, 0);
        if (typedArrayObtainStyledAttributes.getBoolean(14, false)) {
            ActionBarOverlayLayout actionBarOverlayLayout2 = this.c;
            if (!actionBarOverlayLayout2.g) {
                throw new IllegalStateException("Action bar must be in overlay mode (Window.FEATURE_OVERLAY_ACTION_BAR) to enable hide on content scroll");
            }
            this.v = true;
            actionBarOverlayLayout2.setHideOnContentScrollEnabled(true);
        }
        int dimensionPixelSize = typedArrayObtainStyledAttributes.getDimensionPixelSize(12, 0);
        if (dimensionPixelSize != 0) {
            ActionBarContainer actionBarContainer2 = this.d;
            WeakHashMap weakHashMap = V.a;
            androidx.core.view.L.k(actionBarContainer2, dimensionPixelSize);
        }
        typedArrayObtainStyledAttributes.recycle();
    }

    public final void H(int i, int i2) {
        x1 x1Var = (x1) this.e;
        int i3 = x1Var.b;
        if ((i2 & 4) != 0) {
            this.h = true;
        }
        x1Var.a((i & i2) | ((~i2) & i3));
    }

    public final void I(boolean z2) {
        if (z2) {
            this.d.setTabContainer(null);
            ((x1) this.e).getClass();
        } else {
            ((x1) this.e).getClass();
            this.d.setTabContainer(null);
        }
        x1 x1Var = (x1) this.e;
        x1Var.getClass();
        x1Var.a.setCollapsible(false);
        this.c.setHasNonEmbeddedTabs(false);
    }

    public final void J(boolean z2) {
        int i = 0;
        boolean z3 = this.r || !(this.p || this.q);
        View view = this.g;
        Q q = this.y;
        if (!z3) {
            if (this.s) {
                this.s = false;
                androidx.appcompat.view.k kVar = this.t;
                if (kVar != null) {
                    kVar.a();
                }
                int i2 = this.n;
                P p = this.w;
                if (i2 != 0 || (!this.u && !z2)) {
                    p.c();
                    return;
                }
                this.d.setAlpha(1.0f);
                this.d.setTransitioning(true);
                androidx.appcompat.view.k kVar2 = new androidx.appcompat.view.k();
                float f = -this.d.getHeight();
                if (z2) {
                    this.d.getLocationInWindow(new int[]{0, 0});
                    f -= r12[1];
                }
                C1043d0 c1043d0A = V.a(this.d);
                c1043d0A.e(f);
                View view2 = (View) c1043d0A.a.get();
                if (view2 != null) {
                    view2.animate().setUpdateListener(q != null ? new C1039b0(i, q, view2) : null);
                }
                boolean z4 = kVar2.e;
                ArrayList arrayList = kVar2.a;
                if (!z4) {
                    arrayList.add(c1043d0A);
                }
                if (this.o && view != null) {
                    C1043d0 c1043d0A2 = V.a(view);
                    c1043d0A2.e(f);
                    if (!kVar2.e) {
                        arrayList.add(c1043d0A2);
                    }
                }
                AccelerateInterpolator accelerateInterpolator = z;
                boolean z5 = kVar2.e;
                if (!z5) {
                    kVar2.c = accelerateInterpolator;
                }
                if (!z5) {
                    kVar2.b = 250L;
                }
                if (!z5) {
                    kVar2.d = p;
                }
                this.t = kVar2;
                kVar2.b();
                return;
            }
            return;
        }
        if (this.s) {
            return;
        }
        this.s = true;
        androidx.appcompat.view.k kVar3 = this.t;
        if (kVar3 != null) {
            kVar3.a();
        }
        this.d.setVisibility(0);
        int i3 = this.n;
        P p2 = this.x;
        if (i3 == 0 && (this.u || z2)) {
            this.d.setTranslationY(DefinitionKt.NO_Float_VALUE);
            float f2 = -this.d.getHeight();
            if (z2) {
                this.d.getLocationInWindow(new int[]{0, 0});
                f2 -= r12[1];
            }
            this.d.setTranslationY(f2);
            androidx.appcompat.view.k kVar4 = new androidx.appcompat.view.k();
            C1043d0 c1043d0A3 = V.a(this.d);
            c1043d0A3.e(DefinitionKt.NO_Float_VALUE);
            View view3 = (View) c1043d0A3.a.get();
            if (view3 != null) {
                view3.animate().setUpdateListener(q != null ? new C1039b0(i, q, view3) : null);
            }
            boolean z6 = kVar4.e;
            ArrayList arrayList2 = kVar4.a;
            if (!z6) {
                arrayList2.add(c1043d0A3);
            }
            if (this.o && view != null) {
                view.setTranslationY(f2);
                C1043d0 c1043d0A4 = V.a(view);
                c1043d0A4.e(DefinitionKt.NO_Float_VALUE);
                if (!kVar4.e) {
                    arrayList2.add(c1043d0A4);
                }
            }
            DecelerateInterpolator decelerateInterpolator = A;
            boolean z7 = kVar4.e;
            if (!z7) {
                kVar4.c = decelerateInterpolator;
            }
            if (!z7) {
                kVar4.b = 250L;
            }
            if (!z7) {
                kVar4.d = p2;
            }
            this.t = kVar4;
            kVar4.b();
        } else {
            this.d.setAlpha(1.0f);
            this.d.setTranslationY(DefinitionKt.NO_Float_VALUE);
            if (this.o && view != null) {
                view.setTranslationY(DefinitionKt.NO_Float_VALUE);
            }
            p2.c();
        }
        ActionBarOverlayLayout actionBarOverlayLayout = this.c;
        if (actionBarOverlayLayout != null) {
            WeakHashMap weakHashMap = V.a;
            androidx.core.view.J.c(actionBarOverlayLayout);
        }
    }

    @Override // com.bumptech.glide.c
    public final boolean g() {
        s1 s1Var;
        InterfaceC0096l0 interfaceC0096l0 = this.e;
        if (interfaceC0096l0 == null || (s1Var = ((x1) interfaceC0096l0).a.M) == null || s1Var.b == null) {
            return false;
        }
        s1 s1Var2 = ((x1) interfaceC0096l0).a.M;
        androidx.appcompat.view.menu.p pVar = s1Var2 == null ? null : s1Var2.b;
        if (pVar == null) {
            return true;
        }
        pVar.collapseActionView();
        return true;
    }

    @Override // com.bumptech.glide.c
    public final void h(boolean z2) {
        if (z2 == this.l) {
            return;
        }
        this.l = z2;
        ArrayList arrayList = this.m;
        if (arrayList.size() <= 0) {
            return;
        }
        arrayList.get(0).getClass();
        throw new ClassCastException();
    }

    @Override // com.bumptech.glide.c
    public final int i() {
        return ((x1) this.e).b;
    }

    @Override // com.bumptech.glide.c
    public final Context j() {
        if (this.b == null) {
            TypedValue typedValue = new TypedValue();
            this.a.getTheme().resolveAttribute(com.quizlet.quizletandroid.R.attr.actionBarWidgetTheme, typedValue, true);
            int i = typedValue.resourceId;
            if (i != 0) {
                this.b = new ContextThemeWrapper(this.a, i);
            } else {
                this.b = this.a;
            }
        }
        return this.b;
    }

    @Override // com.bumptech.glide.c
    public final void k() {
        if (this.p) {
            return;
        }
        this.p = true;
        J(false);
    }

    @Override // com.bumptech.glide.c
    public final void m() {
        I(androidx.appcompat.view.a.a(this.a).a.getResources().getBoolean(com.quizlet.quizletandroid.R.bool.abc_action_bar_embed_tabs));
    }

    @Override // com.bumptech.glide.c
    public final boolean o(int i, KeyEvent keyEvent) {
        androidx.appcompat.view.menu.n nVar;
        S s = this.i;
        if (s == null || (nVar = s.d) == null) {
            return false;
        }
        nVar.setQwertyMode(KeyCharacterMap.load(keyEvent.getDeviceId()).getKeyboardType() != 1);
        return nVar.performShortcut(i, keyEvent, 0);
    }

    @Override // com.bumptech.glide.c
    public final void r(boolean z2) {
        if (this.h) {
            return;
        }
        s(z2);
    }

    @Override // com.bumptech.glide.c
    public final void s(boolean z2) {
        H(z2 ? 4 : 0, 4);
    }

    @Override // com.bumptech.glide.c
    public final void t() {
        H(2, 2);
    }

    @Override // com.bumptech.glide.c
    public final void u(boolean z2) {
        H(z2 ? 8 : 0, 8);
    }

    @Override // com.bumptech.glide.c
    public final void v(Drawable drawable) {
        x1 x1Var = (x1) this.e;
        x1Var.f = drawable;
        int i = x1Var.b & 4;
        Toolbar toolbar = x1Var.a;
        if (i == 0) {
            toolbar.setNavigationIcon((Drawable) null);
            return;
        }
        if (drawable == null) {
            drawable = x1Var.o;
        }
        toolbar.setNavigationIcon(drawable);
    }

    @Override // com.bumptech.glide.c
    public final void w() {
        this.e.getClass();
    }

    @Override // com.bumptech.glide.c
    public final void x() {
        x1 x1Var = (x1) this.e;
        x1Var.e = null;
        x1Var.c();
    }

    @Override // com.bumptech.glide.c
    public final void y(boolean z2) {
        androidx.appcompat.view.k kVar;
        this.u = z2;
        if (z2 || (kVar = this.t) == null) {
            return;
        }
        kVar.a();
    }

    @Override // com.bumptech.glide.c
    public final void z() {
        A(this.a.getString(com.quizlet.quizletandroid.R.string.quizlet_live));
    }

    public T(Dialog dialog) {
        new ArrayList();
        this.m = new ArrayList();
        this.n = 0;
        this.o = true;
        this.s = true;
        this.w = new P(this, 0);
        this.x = new P(this, 1);
        this.y = new Q(this);
        G(dialog.getWindow().getDecorView());
    }
}
