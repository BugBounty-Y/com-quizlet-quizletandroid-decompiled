package androidx.appcompat.widget;

import android.view.View;
import android.view.ViewConfiguration;

/* renamed from: androidx.appcompat.widget.x0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractViewOnTouchListenerC0119x0 implements View.OnTouchListener, View.OnAttachStateChangeListener {
    public final float a;
    public final int b;
    public final int c;
    public final View d;
    public RunnableC0117w0 e;
    public RunnableC0117w0 f;
    public boolean g;
    public int h;
    public final int[] i = new int[2];

    public AbstractViewOnTouchListenerC0119x0(View view) {
        this.d = view;
        view.setLongClickable(true);
        view.addOnAttachStateChangeListener(this);
        this.a = ViewConfiguration.get(view.getContext()).getScaledTouchSlop();
        int tapTimeout = ViewConfiguration.getTapTimeout();
        this.b = tapTimeout;
        this.c = (ViewConfiguration.getLongPressTimeout() + tapTimeout) / 2;
    }

    public final void a() {
        RunnableC0117w0 runnableC0117w0 = this.f;
        View view = this.d;
        if (runnableC0117w0 != null) {
            view.removeCallbacks(runnableC0117w0);
        }
        RunnableC0117w0 runnableC0117w02 = this.e;
        if (runnableC0117w02 != null) {
            view.removeCallbacks(runnableC0117w02);
        }
    }

    public abstract androidx.appcompat.view.menu.D b();

    public abstract boolean c();

    public boolean d() {
        androidx.appcompat.view.menu.D dB = b();
        if (dB == null || !dB.a()) {
            return true;
        }
        dB.dismiss();
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x005c  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0062  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00cb  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x0100  */
    @Override // android.view.View.OnTouchListener
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean onTouch(android.view.View r13, android.view.MotionEvent r14) throws java.lang.IllegalAccessException, java.lang.IllegalArgumentException {
        /*
            Method dump skipped, instructions count: 284
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.AbstractViewOnTouchListenerC0119x0.onTouch(android.view.View, android.view.MotionEvent):boolean");
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewAttachedToWindow(View view) {
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewDetachedFromWindow(View view) {
        this.g = false;
        this.h = -1;
        RunnableC0117w0 runnableC0117w0 = this.e;
        if (runnableC0117w0 != null) {
            this.d.removeCallbacks(runnableC0117w0);
        }
    }
}
