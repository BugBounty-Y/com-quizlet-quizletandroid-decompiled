package androidx.recyclerview.widget;

import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class J extends GestureDetector.SimpleOnGestureListener {
    public boolean a = true;
    public final /* synthetic */ L b;

    public J(L l) {
        this.b = l;
    }

    @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
    public final boolean onDown(MotionEvent motionEvent) {
        return true;
    }

    @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
    public final void onLongPress(MotionEvent motionEvent) {
        L l;
        View viewK;
        F0 f0O;
        if (this.a && (viewK = (l = this.b).k(motionEvent)) != null && (f0O = l.r.O(viewK)) != null && l.m.hasDragFlag(l.r, f0O)) {
            int pointerId = motionEvent.getPointerId(0);
            int i = l.l;
            if (pointerId == i) {
                int iFindPointerIndex = motionEvent.findPointerIndex(i);
                float x = motionEvent.getX(iFindPointerIndex);
                float y = motionEvent.getY(iFindPointerIndex);
                l.d = x;
                l.e = y;
                l.i = DefinitionKt.NO_Float_VALUE;
                l.h = DefinitionKt.NO_Float_VALUE;
                if (l.m.isLongPressDragEnabled()) {
                    l.p(f0O, 2);
                }
            }
        }
    }
}
