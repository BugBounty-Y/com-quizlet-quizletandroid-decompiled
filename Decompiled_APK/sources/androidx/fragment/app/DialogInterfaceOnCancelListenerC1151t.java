package androidx.fragment.app;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.quizlet.quizletandroid.R;

/* renamed from: androidx.fragment.app.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class DialogInterfaceOnCancelListenerC1151t extends Fragment implements DialogInterface.OnCancelListener, DialogInterface.OnDismissListener {
    public Handler a;
    public boolean j;
    public Dialog l;
    public boolean m;
    public boolean n;
    public boolean o;
    public final B0 b = new B0(this, 1);
    public final DialogInterfaceOnCancelListenerC1148p c = new DialogInterfaceOnCancelListenerC1148p(this);
    public final DialogInterfaceOnDismissListenerC1149q d = new DialogInterfaceOnDismissListenerC1149q(this);
    public int e = 0;
    public int f = 0;
    public boolean g = true;
    public boolean h = true;
    public int i = -1;
    public final r k = new r(this);
    public boolean p = false;

    public void G() {
        H(false, false);
    }

    public final void H(boolean z, boolean z2) {
        if (this.n) {
            return;
        }
        this.n = true;
        this.o = false;
        Dialog dialog = this.l;
        if (dialog != null) {
            dialog.setOnDismissListener(null);
            this.l.dismiss();
            if (!z2) {
                if (Looper.myLooper() == this.a.getLooper()) {
                    onDismiss(this.l);
                } else {
                    this.a.post(this.b);
                }
            }
        }
        this.m = true;
        if (this.i >= 0) {
            AbstractC1136h0 parentFragmentManager = getParentFragmentManager();
            int i = this.i;
            parentFragmentManager.getClass();
            if (i < 0) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Bad id: "));
            }
            parentFragmentManager.y(new C1132f0(parentFragmentManager, null, i, 1), z);
            this.i = -1;
            return;
        }
        AbstractC1136h0 parentFragmentManager2 = getParentFragmentManager();
        C1121a c1121aB = androidx.compose.ui.node.B.b(parentFragmentManager2, parentFragmentManager2);
        c1121aB.p = true;
        c1121aB.k(this);
        if (z) {
            c1121aB.h(true, true);
        } else {
            c1121aB.g();
        }
    }

    public int I() {
        return this.f;
    }

    public void J() {
        G();
    }

    public Dialog K(Bundle bundle) {
        if (AbstractC1136h0.N(3)) {
            toString();
        }
        return new androidx.activity.u(requireContext(), I());
    }

    public final Dialog L() {
        Dialog dialog = this.l;
        if (dialog != null) {
            return dialog;
        }
        throw new IllegalStateException("DialogFragment " + this + " does not have a Dialog.");
    }

    public final void M() {
        if (AbstractC1136h0.N(2)) {
            toString();
        }
        this.e = 0;
        this.f = R.style.OTSDKTheme;
    }

    public void N(Dialog dialog, int i) {
        if (i != 1 && i != 2) {
            if (i != 3) {
                return;
            }
            Window window = dialog.getWindow();
            if (window != null) {
                window.addFlags(24);
            }
        }
        dialog.requestWindowFeature(1);
    }

    public void O(AbstractC1136h0 abstractC1136h0, String str) {
        this.n = false;
        this.o = true;
        C1121a c1121aB = androidx.compose.ui.node.B.b(abstractC1136h0, abstractC1136h0);
        c1121aB.p = true;
        c1121aB.i(0, this, str, 1);
        c1121aB.g();
    }

    @Override // androidx.fragment.app.Fragment
    public final L createFragmentContainer() {
        return new C1150s(this, super.createFragmentContainer());
    }

    @Override // androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        super.onAttach(context);
        getViewLifecycleOwnerLiveData().g(this.k);
        if (this.o) {
            return;
        }
        this.n = false;
    }

    @Override // android.content.DialogInterface.OnCancelListener
    public void onCancel(DialogInterface dialogInterface) {
    }

    @Override // androidx.fragment.app.Fragment
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.a = new Handler();
        this.h = this.mContainerId == 0;
        if (bundle != null) {
            this.e = bundle.getInt("android:style", 0);
            this.f = bundle.getInt("android:theme", 0);
            this.g = bundle.getBoolean("android:cancelable", true);
            this.h = bundle.getBoolean("android:showsDialog", this.h);
            this.i = bundle.getInt("android:backStackId", -1);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        Dialog dialog = this.l;
        if (dialog != null) {
            this.m = true;
            dialog.setOnDismissListener(null);
            this.l.dismiss();
            if (!this.n) {
                onDismiss(this.l);
            }
            this.l = null;
            this.p = false;
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onDetach() {
        super.onDetach();
        if (!this.o && !this.n) {
            this.n = true;
        }
        getViewLifecycleOwnerLiveData().k(this.k);
    }

    @Override // android.content.DialogInterface.OnDismissListener
    public void onDismiss(DialogInterface dialogInterface) {
        if (this.m) {
            return;
        }
        if (AbstractC1136h0.N(3)) {
            toString();
        }
        H(true, true);
    }

    @Override // androidx.fragment.app.Fragment
    public LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        boolean z = this.h;
        if (z && !this.j) {
            if (z && !this.p) {
                try {
                    this.j = true;
                    Dialog dialogK = K(bundle);
                    this.l = dialogK;
                    if (this.h) {
                        N(dialogK, this.e);
                        Context context = getContext();
                        if (context instanceof Activity) {
                            this.l.setOwnerActivity((Activity) context);
                        }
                        this.l.setCancelable(this.g);
                        this.l.setOnCancelListener(this.c);
                        this.l.setOnDismissListener(this.d);
                        this.p = true;
                    } else {
                        this.l = null;
                    }
                    this.j = false;
                } catch (Throwable th) {
                    this.j = false;
                    throw th;
                }
            }
            if (AbstractC1136h0.N(2)) {
                toString();
            }
            Dialog dialog = this.l;
            if (dialog != null) {
                return layoutInflaterOnGetLayoutInflater.cloneInContext(dialog.getContext());
            }
        } else if (AbstractC1136h0.N(2)) {
            toString();
        }
        return layoutInflaterOnGetLayoutInflater;
    }

    @Override // androidx.fragment.app.Fragment
    public void onSaveInstanceState(Bundle bundle) {
        Dialog dialog = this.l;
        if (dialog != null) {
            Bundle bundleOnSaveInstanceState = dialog.onSaveInstanceState();
            bundleOnSaveInstanceState.putBoolean("android:dialogShowing", false);
            bundle.putBundle("android:savedDialogState", bundleOnSaveInstanceState);
        }
        int i = this.e;
        if (i != 0) {
            bundle.putInt("android:style", i);
        }
        int i2 = this.f;
        if (i2 != 0) {
            bundle.putInt("android:theme", i2);
        }
        boolean z = this.g;
        if (!z) {
            bundle.putBoolean("android:cancelable", z);
        }
        boolean z2 = this.h;
        if (!z2) {
            bundle.putBoolean("android:showsDialog", z2);
        }
        int i3 = this.i;
        if (i3 != -1) {
            bundle.putInt("android:backStackId", i3);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onStart() {
        super.onStart();
        Dialog dialog = this.l;
        if (dialog != null) {
            this.m = false;
            dialog.show();
            View decorView = this.l.getWindow().getDecorView();
            androidx.lifecycle.p0.n(decorView, this);
            androidx.lifecycle.p0.o(decorView, this);
            AbstractC3347h2.e(decorView, this);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onStop() {
        super.onStop();
        Dialog dialog = this.l;
        if (dialog != null) {
            dialog.hide();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onViewStateRestored(Bundle bundle) {
        Bundle bundle2;
        super.onViewStateRestored(bundle);
        if (this.l == null || bundle == null || (bundle2 = bundle.getBundle("android:savedDialogState")) == null) {
            return;
        }
        this.l.onRestoreInstanceState(bundle2);
    }

    public void p(int i) {
        G();
    }

    @Override // androidx.fragment.app.Fragment
    public final void performCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        Bundle bundle2;
        super.performCreateView(layoutInflater, viewGroup, bundle);
        if (this.mView != null || this.l == null || bundle == null || (bundle2 = bundle.getBundle("android:savedDialogState")) == null) {
            return;
        }
        this.l.onRestoreInstanceState(bundle2);
    }
}
