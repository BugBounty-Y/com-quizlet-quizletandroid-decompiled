package androidx.recyclerview.widget;

import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class F implements InterfaceC1388r0 {
    public final /* synthetic */ L a;

    public F(L l) {
        this.a = l;
    }

    @Override // androidx.recyclerview.widget.InterfaceC1388r0
    public final void a(MotionEvent motionEvent) {
        L l = this.a;
        l.x.onTouchEvent(motionEvent);
        VelocityTracker velocityTracker = l.t;
        if (velocityTracker != null) {
            velocityTracker.addMovement(motionEvent);
        }
        if (l.l == -1) {
            return;
        }
        int actionMasked = motionEvent.getActionMasked();
        int iFindPointerIndex = motionEvent.findPointerIndex(l.l);
        if (iFindPointerIndex >= 0) {
            l.h(actionMasked, iFindPointerIndex, motionEvent);
        }
        F0 f0 = l.c;
        if (f0 == null) {
            return;
        }
        if (actionMasked != 1) {
            if (actionMasked == 2) {
                if (iFindPointerIndex >= 0) {
                    l.q(l.o, iFindPointerIndex, motionEvent);
                    l.n(f0);
                    RecyclerView recyclerView = l.r;
                    RunnableC1396y runnableC1396y = l.s;
                    recyclerView.removeCallbacks(runnableC1396y);
                    runnableC1396y.run();
                    l.r.invalidate();
                    return;
                }
                return;
            }
            if (actionMasked != 3) {
                if (actionMasked != 6) {
                    return;
                }
                int actionIndex = motionEvent.getActionIndex();
                if (motionEvent.getPointerId(actionIndex) == l.l) {
                    l.l = motionEvent.getPointerId(actionIndex == 0 ? 1 : 0);
                    l.q(l.o, actionIndex, motionEvent);
                    return;
                }
                return;
            }
            VelocityTracker velocityTracker2 = l.t;
            if (velocityTracker2 != null) {
                velocityTracker2.clear();
            }
        }
        l.p(null, 0);
        l.l = -1;
    }

    @Override // androidx.recyclerview.widget.InterfaceC1388r0
    public final boolean d(MotionEvent motionEvent) {
        int iFindPointerIndex;
        L l = this.a;
        l.x.onTouchEvent(motionEvent);
        int actionMasked = motionEvent.getActionMasked();
        G g = null;
        if (actionMasked == 0) {
            l.l = motionEvent.getPointerId(0);
            l.d = motionEvent.getX();
            l.e = motionEvent.getY();
            VelocityTracker velocityTracker = l.t;
            if (velocityTracker != null) {
                velocityTracker.recycle();
            }
            l.t = VelocityTracker.obtain();
            if (l.c == null) {
                ArrayList arrayList = l.p;
                if (!arrayList.isEmpty()) {
                    View viewK = l.k(motionEvent);
                    int size = arrayList.size() - 1;
                    while (true) {
                        if (size < 0) {
                            break;
                        }
                        G g2 = (G) arrayList.get(size);
                        if (g2.e.itemView == viewK) {
                            g = g2;
                            break;
                        }
                        size--;
                    }
                }
                if (g != null) {
                    l.d -= g.i;
                    l.e -= g.j;
                    F0 f0 = g.e;
                    l.j(f0, true);
                    if (l.a.remove(f0.itemView)) {
                        l.m.clearView(l.r, f0);
                    }
                    l.p(f0, g.f);
                    l.q(l.o, 0, motionEvent);
                }
            }
        } else if (actionMasked == 3 || actionMasked == 1) {
            l.l = -1;
            l.p(null, 0);
        } else {
            int i = l.l;
            if (i != -1 && (iFindPointerIndex = motionEvent.findPointerIndex(i)) >= 0) {
                l.h(actionMasked, iFindPointerIndex, motionEvent);
            }
        }
        VelocityTracker velocityTracker2 = l.t;
        if (velocityTracker2 != null) {
            velocityTracker2.addMovement(motionEvent);
        }
        return l.c != null;
    }

    @Override // androidx.recyclerview.widget.InterfaceC1388r0
    public final void e(boolean z) {
        if (z) {
            this.a.p(null, 0);
        }
    }
}
