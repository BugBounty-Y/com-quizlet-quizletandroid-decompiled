package androidx.fragment.app;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.AttributeSet;
import android.view.MenuItem;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.core.app.InterfaceC1015b;
import java.io.FileDescriptor;
import java.io.PrintWriter;

/* loaded from: classes.dex */
public abstract class I extends androidx.activity.s implements InterfaceC1015b {
    public static final /* synthetic */ int a = 0;
    boolean mCreated;
    boolean mResumed;
    final M mFragments = new M(new H(this));
    final androidx.lifecycle.L mFragmentLifecycleRegistry = new androidx.lifecycle.L(this);
    boolean mStopped = true;

    public I() {
        getSavedStateRegistry().c("android:support:lifecycle", new E(this, 0));
        final int i = 0;
        addOnConfigurationChangedListener(new androidx.core.util.a(this) { // from class: androidx.fragment.app.F
            public final /* synthetic */ I b;

            {
                this.b = this;
            }

            @Override // androidx.core.util.a
            public final void accept(Object obj) {
                switch (i) {
                    case 0:
                        this.b.mFragments.a();
                        break;
                    default:
                        this.b.mFragments.a();
                        break;
                }
            }
        });
        final int i2 = 1;
        addOnNewIntentListener(new androidx.core.util.a(this) { // from class: androidx.fragment.app.F
            public final /* synthetic */ I b;

            {
                this.b = this;
            }

            @Override // androidx.core.util.a
            public final void accept(Object obj) {
                switch (i2) {
                    case 0:
                        this.b.mFragments.a();
                        break;
                    default:
                        this.b.mFragments.a();
                        break;
                }
            }
        });
        addOnContextAvailableListener(new androidx.activity.contextaware.b() { // from class: androidx.fragment.app.G
            @Override // androidx.activity.contextaware.b
            public final void a(androidx.activity.s sVar) {
                H h = this.a.mFragments.a;
                h.d.c(h, h, null);
            }
        });
    }

    public static boolean o(AbstractC1136h0 abstractC1136h0) {
        androidx.lifecycle.B b = androidx.lifecycle.B.c;
        boolean zO = false;
        for (Fragment fragment : abstractC1136h0.c.f()) {
            if (fragment != null) {
                if (fragment.getHost() != null) {
                    zO |= o(fragment.getChildFragmentManager());
                }
                A0 a0 = fragment.mViewLifecycleOwner;
                if (a0 != null) {
                    a0.b();
                    if (a0.e.d.a(androidx.lifecycle.B.d)) {
                        fragment.mViewLifecycleOwner.e.g(b);
                        zO = true;
                    }
                }
                if (fragment.mLifecycleRegistry.d.a(androidx.lifecycle.B.d)) {
                    fragment.mLifecycleRegistry.g(b);
                    zO = true;
                }
            }
        }
        return zO;
    }

    public final View dispatchFragmentsOnCreateView(View view, @NonNull String str, @NonNull Context context, @NonNull AttributeSet attributeSet) {
        return this.mFragments.a.d.f.onCreateView(view, str, context, attributeSet);
    }

    @Override // android.app.Activity
    public void dump(@NonNull String str, FileDescriptor fileDescriptor, @NonNull PrintWriter printWriter, String[] strArr) {
        super.dump(str, fileDescriptor, printWriter, strArr);
        if (shouldDumpInternalState(strArr)) {
            printWriter.print(str);
            printWriter.print("Local FragmentActivity ");
            printWriter.print(Integer.toHexString(System.identityHashCode(this)));
            printWriter.println(" State:");
            String str2 = str + "  ";
            printWriter.print(str2);
            printWriter.print("mCreated=");
            printWriter.print(this.mCreated);
            printWriter.print(" mResumed=");
            printWriter.print(this.mResumed);
            printWriter.print(" mStopped=");
            printWriter.print(this.mStopped);
            if (getApplication() != null) {
                new androidx.loader.app.g(this, getViewModelStore()).b(str2, fileDescriptor, printWriter, strArr);
            }
            this.mFragments.a.d.w(str, fileDescriptor, printWriter, strArr);
        }
    }

    @NonNull
    public AbstractC1136h0 getSupportFragmentManager() {
        return this.mFragments.a.d;
    }

    @NonNull
    @Deprecated
    public androidx.loader.app.b getSupportLoaderManager() {
        return new androidx.loader.app.g(this, getViewModelStore());
    }

    public void markFragmentsCreated() {
        AbstractC1136h0 supportFragmentManager;
        do {
            supportFragmentManager = getSupportFragmentManager();
            androidx.lifecycle.B b = androidx.lifecycle.B.a;
        } while (o(supportFragmentManager));
    }

    @Override // androidx.activity.s, android.app.Activity
    public void onActivityResult(int i, int i2, Intent intent) {
        this.mFragments.a();
        super.onActivityResult(i, i2, intent);
    }

    @Deprecated
    public void onAttachFragment(@NonNull Fragment fragment) {
    }

    @Override // androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.mFragmentLifecycleRegistry.e(androidx.lifecycle.A.ON_CREATE);
        C1138i0 c1138i0 = this.mFragments.a.d;
        c1138i0.I = false;
        c1138i0.J = false;
        c1138i0.P.g = false;
        c1138i0.v(1);
    }

    @Override // android.app.Activity, android.view.LayoutInflater.Factory2
    public View onCreateView(View view, @NonNull String str, @NonNull Context context, @NonNull AttributeSet attributeSet) {
        View viewDispatchFragmentsOnCreateView = dispatchFragmentsOnCreateView(view, str, context, attributeSet);
        return viewDispatchFragmentsOnCreateView == null ? super.onCreateView(view, str, context, attributeSet) : viewDispatchFragmentsOnCreateView;
    }

    @Override // android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        this.mFragments.a.d.m();
        this.mFragmentLifecycleRegistry.e(androidx.lifecycle.A.ON_DESTROY);
    }

    @Override // androidx.activity.s, android.app.Activity, android.view.Window.Callback
    public boolean onMenuItemSelected(int i, @NonNull MenuItem menuItem) {
        if (super.onMenuItemSelected(i, menuItem)) {
            return true;
        }
        if (i == 6) {
            return this.mFragments.a.d.k(menuItem);
        }
        return false;
    }

    @Override // android.app.Activity
    public void onPause() {
        super.onPause();
        this.mResumed = false;
        this.mFragments.a.d.v(5);
        this.mFragmentLifecycleRegistry.e(androidx.lifecycle.A.ON_PAUSE);
    }

    @Override // android.app.Activity
    public void onPostResume() {
        super.onPostResume();
        onResumeFragments();
    }

    @Override // androidx.activity.s, android.app.Activity
    public void onRequestPermissionsResult(int i, @NonNull String[] strArr, @NonNull int[] iArr) {
        this.mFragments.a();
        super.onRequestPermissionsResult(i, strArr, iArr);
    }

    @Override // android.app.Activity
    public void onResume() {
        this.mFragments.a();
        super.onResume();
        this.mResumed = true;
        this.mFragments.a.d.A(true);
    }

    public void onResumeFragments() {
        this.mFragmentLifecycleRegistry.e(androidx.lifecycle.A.ON_RESUME);
        C1138i0 c1138i0 = this.mFragments.a.d;
        c1138i0.I = false;
        c1138i0.J = false;
        c1138i0.P.g = false;
        c1138i0.v(7);
    }

    @Override // android.app.Activity
    public void onStart() {
        this.mFragments.a();
        super.onStart();
        this.mStopped = false;
        if (!this.mCreated) {
            this.mCreated = true;
            C1138i0 c1138i0 = this.mFragments.a.d;
            c1138i0.I = false;
            c1138i0.J = false;
            c1138i0.P.g = false;
            c1138i0.v(4);
        }
        this.mFragments.a.d.A(true);
        this.mFragmentLifecycleRegistry.e(androidx.lifecycle.A.ON_START);
        C1138i0 c1138i02 = this.mFragments.a.d;
        c1138i02.I = false;
        c1138i02.J = false;
        c1138i02.P.g = false;
        c1138i02.v(5);
    }

    @Override // android.app.Activity
    public void onStateNotSaved() {
        this.mFragments.a();
    }

    @Override // android.app.Activity
    public void onStop() {
        super.onStop();
        this.mStopped = true;
        markFragmentsCreated();
        C1138i0 c1138i0 = this.mFragments.a.d;
        c1138i0.J = true;
        c1138i0.P.g = true;
        c1138i0.v(4);
        this.mFragmentLifecycleRegistry.e(androidx.lifecycle.A.ON_STOP);
    }

    @Override // androidx.core.app.InterfaceC1015b
    @Deprecated
    public final void validateRequestPermissionsRequestCode(int i) {
    }

    @Override // android.app.Activity, android.view.LayoutInflater.Factory
    public View onCreateView(@NonNull String str, @NonNull Context context, @NonNull AttributeSet attributeSet) {
        View viewDispatchFragmentsOnCreateView = dispatchFragmentsOnCreateView(null, str, context, attributeSet);
        return viewDispatchFragmentsOnCreateView == null ? super.onCreateView(str, context, attributeSet) : viewDispatchFragmentsOnCreateView;
    }
}
