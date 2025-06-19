package androidx.appcompat.app;

import android.R;
import android.content.Context;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.core.view.InterfaceC1055l;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3250r6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import java.lang.reflect.InvocationTargetException;

/* loaded from: classes.dex */
public class D extends androidx.activity.u implements InterfaceC0056l {
    public B d;
    public final C e;

    public D(@NonNull Context context) {
        this(context, 0);
    }

    @Override // androidx.activity.u, android.app.Dialog
    public final void addContentView(View view, ViewGroup.LayoutParams layoutParams) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        B b = (B) c();
        b.w();
        ((ViewGroup) b.A.findViewById(R.id.content)).addView(view, layoutParams);
        b.m.b(b.l.getCallback());
    }

    public final AbstractC0061q c() {
        if (this.d == null) {
            ExecutorC0060p executorC0060p = AbstractC0061q.a;
            this.d = new B(getContext(), getWindow(), this, this);
        }
        return this.d;
    }

    public final void d() {
        p0.n(getWindow().getDecorView(), this);
        AbstractC3347h2.e(getWindow().getDecorView(), this);
        androidx.camera.core.impl.utils.executor.i.d(getWindow().getDecorView(), this);
    }

    @Override // android.app.Dialog, android.content.DialogInterface
    public final void dismiss() {
        super.dismiss();
        c().e();
    }

    @Override // android.app.Dialog, android.view.Window.Callback
    public final boolean dispatchKeyEvent(KeyEvent keyEvent) {
        return AbstractC3250r6.c(this.e, getWindow().getDecorView(), this, keyEvent);
    }

    public final boolean e(KeyEvent keyEvent) {
        return super.dispatchKeyEvent(keyEvent);
    }

    @Override // android.app.Dialog
    public final View findViewById(int i) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        B b = (B) c();
        b.w();
        return b.l.findViewById(i);
    }

    @Override // android.app.Dialog
    public final void invalidateOptionsMenu() {
        c().b();
    }

    @Override // androidx.activity.u, android.app.Dialog
    public void onCreate(Bundle bundle) {
        c().a();
        super.onCreate(bundle);
        c().d();
    }

    @Override // androidx.activity.u, android.app.Dialog
    public final void onStop() throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        super.onStop();
        B b = (B) c();
        b.A();
        com.bumptech.glide.c cVar = b.o;
        if (cVar != null) {
            cVar.y(false);
        }
    }

    @Override // androidx.activity.u, android.app.Dialog
    public void setContentView(int i) {
        d();
        c().h(i);
    }

    @Override // android.app.Dialog
    public void setTitle(CharSequence charSequence) {
        super.setTitle(charSequence);
        c().l(charSequence);
    }

    /* JADX WARN: Type inference failed for: r2v2, types: [androidx.appcompat.app.C] */
    public D(Context context, int i) {
        int i2;
        if (i == 0) {
            TypedValue typedValue = new TypedValue();
            context.getTheme().resolveAttribute(com.quizlet.quizletandroid.R.attr.dialogTheme, typedValue, true);
            i2 = typedValue.resourceId;
        } else {
            i2 = i;
        }
        super(context, i2);
        this.e = new InterfaceC1055l() { // from class: androidx.appcompat.app.C
            @Override // androidx.core.view.InterfaceC1055l
            public final boolean superDispatchKeyEvent(KeyEvent keyEvent) {
                return this.a.e(keyEvent);
            }
        };
        AbstractC0061q abstractC0061qC = c();
        if (i == 0) {
            TypedValue typedValue2 = new TypedValue();
            context.getTheme().resolveAttribute(com.quizlet.quizletandroid.R.attr.dialogTheme, typedValue2, true);
            i = typedValue2.resourceId;
        }
        ((B) abstractC0061qC).d1 = i;
        abstractC0061qC.d();
    }

    @Override // androidx.activity.u, android.app.Dialog
    public void setContentView(View view) {
        d();
        c().i(view);
    }

    @Override // android.app.Dialog
    public final void setTitle(int i) {
        super.setTitle(i);
        c().l(getContext().getString(i));
    }

    @Override // androidx.activity.u, android.app.Dialog
    public void setContentView(View view, ViewGroup.LayoutParams layoutParams) {
        d();
        c().j(view, layoutParams);
    }
}
