package androidx.appcompat.view.menu;

import android.content.Context;
import android.view.ActionProvider;
import android.view.View;
import androidx.core.view.AbstractC1040c;

/* loaded from: classes.dex */
public final class q extends AbstractC1040c implements ActionProvider.VisibilityListener {
    public com.airbnb.lottie.network.d b;
    public final ActionProvider c;

    public q(u uVar, Context context, ActionProvider actionProvider) {
        super(context);
        this.c = actionProvider;
    }

    @Override // androidx.core.view.AbstractC1040c
    public final boolean a() {
        return this.c.hasSubMenu();
    }

    @Override // androidx.core.view.AbstractC1040c
    public final boolean b() {
        return this.c.isVisible();
    }

    @Override // androidx.core.view.AbstractC1040c
    public final View c() {
        return this.c.onCreateActionView();
    }

    @Override // androidx.core.view.AbstractC1040c
    public final View d(p pVar) {
        return this.c.onCreateActionView(pVar);
    }

    @Override // androidx.core.view.AbstractC1040c
    public final boolean e() {
        return this.c.onPerformDefaultAction();
    }

    @Override // androidx.core.view.AbstractC1040c
    public final void f(F f) {
        this.c.onPrepareSubMenu(f);
    }

    @Override // androidx.core.view.AbstractC1040c
    public final boolean g() {
        return this.c.overridesItemVisibility();
    }

    @Override // androidx.core.view.AbstractC1040c
    public final void h(com.airbnb.lottie.network.d dVar) {
        this.b = dVar;
        this.c.setVisibilityListener(this);
    }

    @Override // android.view.ActionProvider.VisibilityListener
    public final void onActionProviderVisibilityChanged(boolean z) {
        com.airbnb.lottie.network.d dVar = this.b;
        if (dVar != null) {
            n nVar = ((p) dVar.b).n;
            nVar.h = true;
            nVar.p(true);
        }
    }
}
