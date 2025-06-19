package androidx.recyclerview.widget;

import android.os.Build;
import android.view.animation.BaseInterpolator;
import android.view.animation.Interpolator;
import android.widget.OverScroller;
import androidx.collection.C0210h;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.Arrays;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class E0 implements Runnable {
    public int a;
    public int b;
    public OverScroller c;
    public Interpolator d;
    public boolean e;
    public boolean f;
    public final /* synthetic */ RecyclerView g;

    public E0(RecyclerView recyclerView) {
        this.g = recyclerView;
        H h = RecyclerView.T1;
        this.d = h;
        this.e = false;
        this.f = false;
        this.c = new OverScroller(recyclerView.getContext(), h);
    }

    public final void a(int i, int i2) {
        RecyclerView recyclerView = this.g;
        recyclerView.setScrollState(2);
        this.b = 0;
        this.a = 0;
        Interpolator interpolator = this.d;
        H h = RecyclerView.T1;
        if (interpolator != h) {
            this.d = h;
            this.c = new OverScroller(recyclerView.getContext(), h);
        }
        this.c.fling(0, 0, i, i2, Integer.MIN_VALUE, SubsamplingScaleImageView.TILE_SIZE_AUTO, Integer.MIN_VALUE, SubsamplingScaleImageView.TILE_SIZE_AUTO);
        b();
    }

    public final void b() {
        if (this.e) {
            this.f = true;
            return;
        }
        RecyclerView recyclerView = this.g;
        recyclerView.removeCallbacks(this);
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        recyclerView.postOnAnimation(this);
    }

    public final void c(int i, int i2, int i3, BaseInterpolator baseInterpolator) {
        RecyclerView recyclerView = this.g;
        if (i3 == Integer.MIN_VALUE) {
            int iAbs = Math.abs(i);
            int iAbs2 = Math.abs(i2);
            boolean z = iAbs > iAbs2;
            int width = z ? recyclerView.getWidth() : recyclerView.getHeight();
            if (!z) {
                iAbs = iAbs2;
            }
            i3 = Math.min((int) (((iAbs / width) + 1.0f) * 300.0f), 2000);
        }
        int i4 = i3;
        Interpolator interpolator = baseInterpolator;
        if (baseInterpolator == null) {
            interpolator = RecyclerView.T1;
        }
        if (this.d != interpolator) {
            this.d = interpolator;
            this.c = new OverScroller(recyclerView.getContext(), interpolator);
        }
        this.b = 0;
        this.a = 0;
        recyclerView.setScrollState(2);
        this.c.startScroll(0, 0, i, i2, i4);
        b();
    }

    @Override // java.lang.Runnable
    public final void run() {
        int i;
        int i2;
        int i3;
        int i4;
        RecyclerView recyclerView = this.g;
        if (recyclerView.n == null) {
            recyclerView.removeCallbacks(this);
            this.c.abortAnimation();
            return;
        }
        this.f = false;
        this.e = true;
        recyclerView.q();
        OverScroller overScroller = this.c;
        if (overScroller.computeScrollOffset()) {
            int currX = overScroller.getCurrX();
            int currY = overScroller.getCurrY();
            int i5 = currX - this.a;
            int i6 = currY - this.b;
            this.a = currX;
            this.b = currY;
            int iP = RecyclerView.p(i5, recyclerView.I, recyclerView.K, recyclerView.getWidth());
            int iP2 = RecyclerView.p(i6, recyclerView.J, recyclerView.L, recyclerView.getHeight());
            int[] iArr = recyclerView.D1;
            iArr[0] = 0;
            iArr[1] = 0;
            boolean zW = recyclerView.w(iP, iP2, 1, iArr, null);
            int[] iArr2 = recyclerView.D1;
            if (zW) {
                iP -= iArr2[0];
                iP2 -= iArr2[1];
            }
            if (recyclerView.getOverScrollMode() != 2) {
                recyclerView.o(iP, iP2);
            }
            if (recyclerView.m != null) {
                iArr2[0] = 0;
                iArr2[1] = 0;
                recyclerView.j0(iP, iP2, iArr2);
                int i7 = iArr2[0];
                int i8 = iArr2[1];
                int i9 = iP - i7;
                int i10 = iP2 - i8;
                S s = recyclerView.n.e;
                if (s != null && !s.d && s.e) {
                    int iB = recyclerView.r1.b();
                    if (iB == 0) {
                        s.k();
                    } else if (s.a >= iB) {
                        s.a = iB - 1;
                        s.i(i7, i8);
                    } else {
                        s.i(i7, i8);
                    }
                }
                i = i9;
                i3 = i7;
                i2 = i10;
                i4 = i8;
            } else {
                i = iP;
                i2 = iP2;
                i3 = 0;
                i4 = 0;
            }
            if (!recyclerView.p.isEmpty()) {
                recyclerView.invalidate();
            }
            int[] iArr3 = recyclerView.D1;
            iArr3[0] = 0;
            iArr3[1] = 0;
            recyclerView.x(i3, i4, i, i2, null, 1, iArr3);
            int i11 = i - iArr2[0];
            int i12 = i2 - iArr2[1];
            if (i3 != 0 || i4 != 0) {
                recyclerView.y(i3, i4);
            }
            if (!recyclerView.awakenScrollBars()) {
                recyclerView.invalidate();
            }
            boolean z = overScroller.isFinished() || (((overScroller.getCurrX() == overScroller.getFinalX()) || i11 != 0) && ((overScroller.getCurrY() == overScroller.getFinalY()) || i12 != 0));
            S s2 = recyclerView.n.e;
            if ((s2 == null || !s2.d) && z) {
                if (recyclerView.getOverScrollMode() != 2) {
                    int currVelocity = (int) overScroller.getCurrVelocity();
                    int i13 = i11 < 0 ? -currVelocity : i11 > 0 ? currVelocity : 0;
                    if (i12 < 0) {
                        currVelocity = -currVelocity;
                    } else if (i12 <= 0) {
                        currVelocity = 0;
                    }
                    if (i13 < 0) {
                        recyclerView.A();
                        if (recyclerView.I.isFinished()) {
                            recyclerView.I.onAbsorb(-i13);
                        }
                    } else if (i13 > 0) {
                        recyclerView.B();
                        if (recyclerView.K.isFinished()) {
                            recyclerView.K.onAbsorb(i13);
                        }
                    }
                    if (currVelocity < 0) {
                        recyclerView.C();
                        if (recyclerView.J.isFinished()) {
                            recyclerView.J.onAbsorb(-currVelocity);
                        }
                    } else if (currVelocity > 0) {
                        recyclerView.z();
                        if (recyclerView.L.isFinished()) {
                            recyclerView.L.onAbsorb(currVelocity);
                        }
                    }
                    if (i13 != 0 || currVelocity != 0) {
                        recyclerView.postInvalidateOnAnimation();
                    }
                }
                if (RecyclerView.R1) {
                    C0210h c0210h = recyclerView.q1;
                    int[] iArr4 = c0210h.c;
                    if (iArr4 != null) {
                        Arrays.fill(iArr4, -1);
                    }
                    c0210h.d = 0;
                }
            } else {
                b();
                D d = recyclerView.p1;
                if (d != null) {
                    d.a(recyclerView, i3, i4);
                }
            }
            if (Build.VERSION.SDK_INT >= 35) {
                AbstractC1367g0.a(recyclerView, Math.abs(overScroller.getCurrVelocity()));
            }
        }
        S s3 = recyclerView.n.e;
        if (s3 != null && s3.d) {
            s3.i(0, 0);
        }
        this.e = false;
        if (!this.f) {
            recyclerView.setScrollState(0);
            recyclerView.r0(1);
        } else {
            recyclerView.removeCallbacks(this);
            WeakHashMap weakHashMap = androidx.core.view.V.a;
            recyclerView.postOnAnimation(this);
        }
    }
}
