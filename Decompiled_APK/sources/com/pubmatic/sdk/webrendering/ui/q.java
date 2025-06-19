package com.pubmatic.sdk.webrendering.ui;

import android.view.View;
import android.view.ViewTreeObserver;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class q implements ViewTreeObserver.OnGlobalLayoutListener, ViewTreeObserver.OnScrollChangedListener, ViewTreeObserver.OnWindowFocusChangeListener, View.OnAttachStateChangeListener {

    @NonNull
    private View a;
    private p b;
    private float c;
    private int d;
    private boolean e;
    private boolean f;

    public q(@NonNull View view) {
        this.a = view;
        this.f = false;
        this.e = false;
        view.addOnAttachStateChangeListener(this);
    }

    private void a() {
        if (this.a.getViewTreeObserver().isAlive()) {
            this.a.getViewTreeObserver().addOnWindowFocusChangeListener(this);
        }
    }

    private void b() {
        if (this.a.getViewTreeObserver().isAlive()) {
            this.a.getViewTreeObserver().addOnGlobalLayoutListener(this);
            this.a.getViewTreeObserver().addOnScrollChangedListener(this);
        }
    }

    private void c() {
        if (this.a.getViewTreeObserver().isAlive()) {
            this.a.getViewTreeObserver().removeOnWindowFocusChangeListener(this);
        }
    }

    private void d() {
        if (this.a.getViewTreeObserver().isAlive()) {
            this.a.getViewTreeObserver().removeOnGlobalLayoutListener(this);
            this.a.getViewTreeObserver().removeOnScrollChangedListener(this);
        }
    }

    private void e() {
        int i = this.d;
        boolean z = false;
        if (i != 0) {
            if (com.pubmatic.sdk.common.utility.o.isViewVisible(this.a, i) && this.a.hasWindowFocus()) {
                z = true;
            }
            p pVar = this.b;
            if (pVar != null) {
                pVar.onViewabilityChanged(z);
            }
            this.f = z;
            return;
        }
        if (com.pubmatic.sdk.common.utility.o.getVisiblePercent(this.a) >= this.c && this.a.hasWindowFocus()) {
            z = true;
        }
        if (this.f != z) {
            p pVar2 = this.b;
            if (pVar2 != null) {
                pVar2.onViewabilityChanged(z);
            }
            this.f = z;
        }
    }

    public void destroy() {
        d();
        c();
        this.a.removeOnAttachStateChangeListener(this);
    }

    public boolean isViewable() {
        return this.f;
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public void onGlobalLayout() {
        e();
    }

    @Override // android.view.ViewTreeObserver.OnScrollChangedListener
    public void onScrollChanged() {
        e();
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public void onViewAttachedToWindow(View view) {
        a();
        if (this.e) {
            b();
        }
        e();
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public void onViewDetachedFromWindow(View view) {
        d();
        c();
        e();
    }

    @Override // android.view.ViewTreeObserver.OnWindowFocusChangeListener
    public void onWindowFocusChanged(boolean z) {
        e();
    }

    public void setAllowViewTreeObserverRegistration(boolean z) {
        this.e = z;
    }

    public void setOnExposureChangeWithThresholdListener(p pVar) {
        this.b = pVar;
    }

    public q(@NonNull View view, float f) {
        this(view);
        this.c = f;
    }

    public q(@NonNull View view, int i) {
        this(view);
        this.d = i;
    }
}
