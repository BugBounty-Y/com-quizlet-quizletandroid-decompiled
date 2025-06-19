package androidx.appcompat.widget;

import android.os.SystemClock;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewParent;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.appcompat.widget.w0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class RunnableC0117w0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ AbstractViewOnTouchListenerC0119x0 b;

    public /* synthetic */ RunnableC0117w0(AbstractViewOnTouchListenerC0119x0 abstractViewOnTouchListenerC0119x0, int i) {
        this.a = i;
        this.b = abstractViewOnTouchListenerC0119x0;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                ViewParent parent = this.b.d.getParent();
                if (parent != null) {
                    parent.requestDisallowInterceptTouchEvent(true);
                    break;
                }
                break;
            default:
                AbstractViewOnTouchListenerC0119x0 abstractViewOnTouchListenerC0119x0 = this.b;
                abstractViewOnTouchListenerC0119x0.a();
                View view = abstractViewOnTouchListenerC0119x0.d;
                if (view.isEnabled() && !view.isLongClickable() && abstractViewOnTouchListenerC0119x0.c()) {
                    view.getParent().requestDisallowInterceptTouchEvent(true);
                    long jUptimeMillis = SystemClock.uptimeMillis();
                    MotionEvent motionEventObtain = MotionEvent.obtain(jUptimeMillis, jUptimeMillis, 3, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0);
                    view.onTouchEvent(motionEventObtain);
                    motionEventObtain.recycle();
                    abstractViewOnTouchListenerC0119x0.g = true;
                    break;
                }
                break;
        }
    }
}
