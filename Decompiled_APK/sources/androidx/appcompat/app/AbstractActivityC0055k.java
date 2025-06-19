package androidx.appcompat.app;

import android.R;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import androidx.appcompat.widget.C0112u;
import androidx.appcompat.widget.N0;
import androidx.appcompat.widget.Toolbar;
import androidx.appcompat.widget.z1;
import androidx.collection.C0219q;
import androidx.core.app.AbstractC1019f;
import androidx.core.app.W;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import java.lang.reflect.InvocationTargetException;

/* renamed from: androidx.appcompat.app.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractActivityC0055k extends androidx.fragment.app.I implements InterfaceC0056l {
    public B b;

    public AbstractActivityC0055k() {
        getSavedStateRegistry().c("androidx:appcompat", new C0053i(this));
        addOnContextAvailableListener(new C0054j(this, 0));
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void addContentView(View view, ViewGroup.LayoutParams layoutParams) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        t();
        B b = (B) q();
        b.w();
        ((ViewGroup) b.A.findViewById(R.id.content)).addView(view, layoutParams);
        b.m.b(b.l.getCallback());
    }

    /* JADX WARN: Removed duplicated region for block: B:165:0x0211 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    @Override // android.app.Activity, android.view.ContextThemeWrapper, android.content.ContextWrapper
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void attachBaseContext(android.content.Context r10) {
        /*
            Method dump skipped, instructions count: 554
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.AbstractActivityC0055k.attachBaseContext(android.content.Context):void");
    }

    @Override // android.app.Activity
    public final void closeOptionsMenu() {
        com.bumptech.glide.c cVarR = r();
        if (getWindow().hasFeature(0)) {
            if (cVarR == null || !cVarR.f()) {
                super.closeOptionsMenu();
            }
        }
    }

    @Override // androidx.core.app.AbstractActivityC1021h, android.app.Activity, android.view.Window.Callback
    public final boolean dispatchKeyEvent(KeyEvent keyEvent) {
        int keyCode = keyEvent.getKeyCode();
        com.bumptech.glide.c cVarR = r();
        if (keyCode == 82 && cVarR != null && cVarR.p(keyEvent)) {
            return true;
        }
        return super.dispatchKeyEvent(keyEvent);
    }

    @Override // android.app.Activity
    public final View findViewById(int i) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        B b = (B) q();
        b.w();
        return b.l.findViewById(i);
    }

    @Override // android.app.Activity
    public final MenuInflater getMenuInflater() throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        B b = (B) q();
        if (b.p == null) {
            b.A();
            com.bumptech.glide.c cVar = b.o;
            b.p = new androidx.appcompat.view.i(cVar != null ? cVar.j() : b.k);
        }
        return b.p;
    }

    @Override // android.view.ContextThemeWrapper, android.content.ContextWrapper, android.content.Context
    public final Resources getResources() {
        int i = z1.a;
        return super.getResources();
    }

    @Override // android.app.Activity
    public final void invalidateOptionsMenu() {
        q().b();
    }

    @Override // androidx.activity.s, android.app.Activity, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) throws IllegalAccessException, NoSuchMethodException, PackageManager.NameNotFoundException, SecurityException, IllegalArgumentException, InvocationTargetException {
        super.onConfigurationChanged(configuration);
        B b = (B) q();
        if (b.F && b.z) {
            b.A();
            com.bumptech.glide.c cVar = b.o;
            if (cVar != null) {
                cVar.m();
            }
        }
        C0112u c0112uA = C0112u.a();
        Context context = b.k;
        synchronized (c0112uA) {
            N0 n0 = c0112uA.a;
            synchronized (n0) {
                C0219q c0219q = (C0219q) n0.b.get(context);
                if (c0219q != null) {
                    c0219q.b();
                }
            }
        }
        b.Z = new Configuration(b.k.getResources().getConfiguration());
        b.m(false, false);
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public final void onContentChanged() {
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        q().e();
    }

    @Override // androidx.fragment.app.I, androidx.activity.s, android.app.Activity, android.view.Window.Callback
    public final boolean onMenuItemSelected(int i, MenuItem menuItem) {
        Intent intentA;
        if (!super.onMenuItemSelected(i, menuItem)) {
            com.bumptech.glide.c cVarR = r();
            if (menuItem.getItemId() != 16908332 || cVarR == null || (cVarR.i() & 4) == 0 || (intentA = AbstractC1019f.a(this)) == null) {
                return false;
            }
            if (!shouldUpRecreateTask(intentA)) {
                navigateUpTo(intentA);
                return true;
            }
            W w = new W(this);
            Intent intentA2 = AbstractC1019f.a(this);
            if (intentA2 == null) {
                intentA2 = AbstractC1019f.a(this);
            }
            if (intentA2 != null) {
                ComponentName component = intentA2.getComponent();
                if (component == null) {
                    component = intentA2.resolveActivity(w.b.getPackageManager());
                }
                w.b(component);
                w.a.add(intentA2);
            }
            w.e();
            try {
                finishAffinity();
            } catch (IllegalStateException unused) {
                finish();
            }
        }
        return true;
    }

    @Override // android.app.Activity
    public void onPostCreate(Bundle bundle) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        super.onPostCreate(bundle);
        ((B) q()).w();
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public final void onPostResume() throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        super.onPostResume();
        B b = (B) q();
        b.A();
        com.bumptech.glide.c cVar = b.o;
        if (cVar != null) {
            cVar.y(true);
        }
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public void onStart() throws PackageManager.NameNotFoundException {
        super.onStart();
        ((B) q()).m(true, false);
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public void onStop() throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        super.onStop();
        B b = (B) q();
        b.A();
        com.bumptech.glide.c cVar = b.o;
        if (cVar != null) {
            cVar.y(false);
        }
    }

    @Override // android.app.Activity
    public final void onTitleChanged(CharSequence charSequence, int i) {
        super.onTitleChanged(charSequence, i);
        q().l(charSequence);
    }

    @Override // android.app.Activity
    public final void openOptionsMenu() {
        com.bumptech.glide.c cVarR = r();
        if (getWindow().hasFeature(0)) {
            if (cVarR == null || !cVarR.q()) {
                super.openOptionsMenu();
            }
        }
    }

    public final AbstractC0061q q() {
        if (this.b == null) {
            ExecutorC0060p executorC0060p = AbstractC0061q.a;
            this.b = new B(this, null, this, this);
        }
        return this.b;
    }

    public final com.bumptech.glide.c r() {
        B b = (B) q();
        b.A();
        return b.o;
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void setContentView(int i) {
        t();
        q().h(i);
    }

    @Override // android.app.Activity, android.view.ContextThemeWrapper, android.content.ContextWrapper, android.content.Context
    public final void setTheme(int i) {
        super.setTheme(i);
        ((B) q()).d1 = i;
    }

    public final void t() {
        p0.n(getWindow().getDecorView(), this);
        p0.o(getWindow().getDecorView(), this);
        AbstractC3347h2.e(getWindow().getDecorView(), this);
        androidx.camera.core.impl.utils.executor.i.d(getWindow().getDecorView(), this);
    }

    public final void v(Toolbar toolbar) {
        B b = (B) q();
        if (b.j instanceof Activity) {
            b.A();
            com.bumptech.glide.c cVar = b.o;
            if (cVar instanceof T) {
                throw new IllegalStateException("This Activity already has an action bar supplied by the window decor. Do not request Window.FEATURE_SUPPORT_ACTION_BAR and set windowActionBar to false in your theme to use a Toolbar instead.");
            }
            b.p = null;
            if (cVar != null) {
                cVar.n();
            }
            b.o = null;
            if (toolbar != null) {
                Object obj = b.j;
                M m = new M(toolbar, obj instanceof Activity ? ((Activity) obj).getTitle() : b.q, b.m);
                b.o = m;
                b.m.a = m.c;
                toolbar.setBackInvokedCallbackEnabled(true);
            } else {
                b.m.a = null;
            }
            b.b();
        }
    }

    @Override // androidx.activity.s, android.app.Activity
    public void setContentView(View view) {
        t();
        q().i(view);
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void setContentView(View view, ViewGroup.LayoutParams layoutParams) {
        t();
        q().j(view, layoutParams);
    }
}
