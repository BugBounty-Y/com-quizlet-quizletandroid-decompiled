package androidx.appcompat.widget;

import android.view.MotionEvent;
import android.view.View;
import com.google.android.gms.internal.ads.P4;

/* loaded from: classes.dex */
public final class F0 implements View.OnTouchListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ F0(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.view.View.OnTouchListener
    public final boolean onTouch(View view, MotionEvent motionEvent) {
        B b;
        switch (this.a) {
            case 0:
                int action = motionEvent.getAction();
                int x = (int) motionEvent.getX();
                int y = (int) motionEvent.getY();
                G0 g0 = (G0) this.b;
                if (action == 0 && (b = g0.z) != null && b.isShowing() && x >= 0 && x < g0.z.getWidth() && y >= 0 && y < g0.z.getHeight()) {
                    g0.v.postDelayed(g0.r, 250L);
                    break;
                } else if (action == 1) {
                    g0.v.removeCallbacks(g0.r);
                    break;
                }
                break;
            default:
                P4 p4 = ((com.google.android.gms.ads.internal.i) this.b).h;
                if (p4 != null) {
                    p4.b.h(motionEvent);
                    break;
                }
                break;
        }
        return false;
    }
}
