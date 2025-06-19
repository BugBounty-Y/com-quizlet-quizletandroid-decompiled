package androidx.fragment.app;

import android.app.Application;
import android.content.Context;
import android.content.ContextWrapper;
import androidx.compose.ui.platform.C0978y0;
import androidx.lifecycle.C1247h;
import androidx.lifecycle.InterfaceC1261w;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class A0 implements InterfaceC1261w, androidx.savedstate.f, androidx.lifecycle.C0 {
    public final Fragment a;
    public final androidx.lifecycle.B0 b;
    public final RunnableC1152u c;
    public androidx.lifecycle.y0 d;
    public androidx.lifecycle.L e = null;
    public androidx.savedstate.e f = null;

    public A0(Fragment fragment, androidx.lifecycle.B0 b0, RunnableC1152u runnableC1152u) {
        this.a = fragment;
        this.b = b0;
        this.c = runnableC1152u;
    }

    public final void a(androidx.lifecycle.A a) {
        this.e.e(a);
    }

    public final void b() {
        if (this.e == null) {
            this.e = new androidx.lifecycle.L(this);
            Intrinsics.checkNotNullParameter(this, "owner");
            C0978y0 c0978y0 = new C0978y0(this, new C1247h(this, 4));
            this.f = new androidx.savedstate.e(c0978y0);
            c0978y0.d();
            this.c.run();
        }
    }

    @Override // androidx.lifecycle.InterfaceC1261w
    public final androidx.lifecycle.viewmodel.c getDefaultViewModelCreationExtras() {
        Application application;
        Fragment fragment = this.a;
        Context applicationContext = fragment.requireContext().getApplicationContext();
        while (true) {
            if (!(applicationContext instanceof ContextWrapper)) {
                application = null;
                break;
            }
            if (applicationContext instanceof Application) {
                application = (Application) applicationContext;
                break;
            }
            applicationContext = ((ContextWrapper) applicationContext).getBaseContext();
        }
        androidx.lifecycle.viewmodel.e eVar = new androidx.lifecycle.viewmodel.e(0);
        if (application != null) {
            eVar.b(androidx.lifecycle.x0.d, application);
        }
        eVar.b(androidx.lifecycle.p0.a, fragment);
        eVar.b(androidx.lifecycle.p0.b, this);
        if (fragment.getArguments() != null) {
            eVar.b(androidx.lifecycle.p0.c, fragment.getArguments());
        }
        return eVar;
    }

    @Override // androidx.lifecycle.InterfaceC1261w
    public final androidx.lifecycle.y0 getDefaultViewModelProviderFactory() {
        Application application;
        Fragment fragment = this.a;
        androidx.lifecycle.y0 defaultViewModelProviderFactory = fragment.getDefaultViewModelProviderFactory();
        if (!defaultViewModelProviderFactory.equals(fragment.mDefaultFactory)) {
            this.d = defaultViewModelProviderFactory;
            return defaultViewModelProviderFactory;
        }
        if (this.d == null) {
            Context applicationContext = fragment.requireContext().getApplicationContext();
            while (true) {
                if (!(applicationContext instanceof ContextWrapper)) {
                    application = null;
                    break;
                }
                if (applicationContext instanceof Application) {
                    application = (Application) applicationContext;
                    break;
                }
                applicationContext = ((ContextWrapper) applicationContext).getBaseContext();
            }
            this.d = new androidx.lifecycle.s0(application, fragment, fragment.getArguments());
        }
        return this.d;
    }

    @Override // androidx.lifecycle.J
    public final androidx.lifecycle.C getLifecycle() {
        b();
        return this.e;
    }

    @Override // androidx.savedstate.f
    public final androidx.savedstate.d getSavedStateRegistry() {
        b();
        return this.f.b;
    }

    @Override // androidx.lifecycle.C0
    public final androidx.lifecycle.B0 getViewModelStore() {
        b();
        return this.b;
    }
}
