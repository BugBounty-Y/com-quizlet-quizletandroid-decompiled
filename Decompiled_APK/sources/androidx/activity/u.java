package androidx.activity;

import android.app.Dialog;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.window.OnBackInvokedDispatcher;
import androidx.compose.ui.platform.C0978y0;
import androidx.lifecycle.C1247h;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public class u extends Dialog implements androidx.lifecycle.J, N, androidx.savedstate.f {
    public androidx.lifecycle.L a;
    public final androidx.savedstate.e b;
    public final L c;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public u(@NotNull Context context) {
        this(context, 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public static void a(u uVar) {
        super.onBackPressed();
    }

    @Override // android.app.Dialog
    public void addContentView(View view, ViewGroup.LayoutParams layoutParams) {
        Intrinsics.checkNotNullParameter(view, "view");
        b();
        super.addContentView(view, layoutParams);
    }

    public final void b() {
        Window window = getWindow();
        Intrinsics.d(window);
        View decorView = window.getDecorView();
        Intrinsics.checkNotNullExpressionValue(decorView, "window!!.decorView");
        p0.n(decorView, this);
        Window window2 = getWindow();
        Intrinsics.d(window2);
        View decorView2 = window2.getDecorView();
        Intrinsics.checkNotNullExpressionValue(decorView2, "window!!.decorView");
        androidx.camera.core.impl.utils.executor.i.d(decorView2, this);
        Window window3 = getWindow();
        Intrinsics.d(window3);
        View decorView3 = window3.getDecorView();
        Intrinsics.checkNotNullExpressionValue(decorView3, "window!!.decorView");
        AbstractC3347h2.e(decorView3, this);
    }

    @Override // androidx.lifecycle.J
    public final androidx.lifecycle.C getLifecycle() {
        androidx.lifecycle.L l = this.a;
        if (l != null) {
            return l;
        }
        androidx.lifecycle.L l2 = new androidx.lifecycle.L(this);
        this.a = l2;
        return l2;
    }

    @Override // androidx.activity.N
    public final L getOnBackPressedDispatcher() {
        return this.c;
    }

    @Override // androidx.savedstate.f
    public final androidx.savedstate.d getSavedStateRegistry() {
        return this.b.b;
    }

    @Override // android.app.Dialog
    public final void onBackPressed() {
        this.c.c();
    }

    @Override // android.app.Dialog
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (Build.VERSION.SDK_INT >= 33) {
            OnBackInvokedDispatcher invoker = getOnBackInvokedDispatcher();
            Intrinsics.checkNotNullExpressionValue(invoker, "onBackInvokedDispatcher");
            L l = this.c;
            l.getClass();
            Intrinsics.checkNotNullParameter(invoker, "invoker");
            l.e = invoker;
            l.d(l.g);
        }
        this.b.a(bundle);
        androidx.lifecycle.L l2 = this.a;
        if (l2 == null) {
            l2 = new androidx.lifecycle.L(this);
            this.a = l2;
        }
        l2.e(androidx.lifecycle.A.ON_CREATE);
    }

    @Override // android.app.Dialog
    public final Bundle onSaveInstanceState() {
        Bundle bundleOnSaveInstanceState = super.onSaveInstanceState();
        Intrinsics.checkNotNullExpressionValue(bundleOnSaveInstanceState, "super.onSaveInstanceState()");
        this.b.b(bundleOnSaveInstanceState);
        return bundleOnSaveInstanceState;
    }

    @Override // android.app.Dialog
    public void onStart() {
        super.onStart();
        androidx.lifecycle.L l = this.a;
        if (l == null) {
            l = new androidx.lifecycle.L(this);
            this.a = l;
        }
        l.e(androidx.lifecycle.A.ON_RESUME);
    }

    @Override // android.app.Dialog
    public void onStop() {
        androidx.lifecycle.L l = this.a;
        if (l == null) {
            l = new androidx.lifecycle.L(this);
            this.a = l;
        }
        l.e(androidx.lifecycle.A.ON_DESTROY);
        this.a = null;
        super.onStop();
    }

    @Override // android.app.Dialog
    public void setContentView(int i) {
        b();
        super.setContentView(i);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(Context context, int i) {
        super(context, i);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(this, "owner");
        this.b = new androidx.savedstate.e(new C0978y0(this, new C1247h(this, 4)));
        this.c = new L(new RunnableC0041m(this, 1));
    }

    @Override // android.app.Dialog
    public void setContentView(View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        b();
        super.setContentView(view);
    }

    @Override // android.app.Dialog
    public void setContentView(View view, ViewGroup.LayoutParams layoutParams) {
        Intrinsics.checkNotNullParameter(view, "view");
        b();
        super.setContentView(view, layoutParams);
    }
}
