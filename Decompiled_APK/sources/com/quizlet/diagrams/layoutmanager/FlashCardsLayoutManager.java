package com.quizlet.diagrams.layoutmanager;

import android.content.Context;
import android.view.View;
import android.view.ViewConfiguration;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.B0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.Z;

/* loaded from: classes2.dex */
public class FlashCardsLayoutManager extends LinearLayoutManager implements a {
    public static final float F = (float) (Math.log(0.78d) / Math.log(0.9d));
    public static final double G = 0.84d;
    public double E;

    public FlashCardsLayoutManager(Context context) {
        super(context);
        this.E = context.getResources().getDisplayMetrics().density * 386.0885886511961d * 160.0d * G;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final void F0(RecyclerView recyclerView, B0 b0, int i) {
        Z z = new Z(3, recyclerView.getContext(), this);
        z.a = i;
        G0(z);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final boolean d() {
        return super.d();
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final boolean e() {
        return super.e();
    }

    public int p1(int i, int i2, int i3, int i4) {
        double dLog = Math.log((Math.abs(i) * 0.3499999940395355d) / (ViewConfiguration.getScrollFriction() * this.E));
        double d = F;
        double dExp = Math.exp((d / (d - 1.0d)) * dLog) * ViewConfiguration.getScrollFriction() * this.E;
        double d2 = i2;
        if (i <= 0) {
            dExp = -dExp;
        }
        double d3 = d2 + dExp;
        if (i < 0) {
            return (int) Math.max((d3 / i3) + i4, 0.0d);
        }
        return (int) ((d3 / i3) + i4 + 1.0d);
    }

    public final int q1() {
        if (v() == 0) {
            return 0;
        }
        View viewU = u(0);
        int iK = AbstractC1381n0.K(viewU);
        return (this.p != 0 || Math.abs(viewU.getLeft()) <= viewU.getMeasuredWidth() / 2) ? (this.p != 1 || Math.abs(viewU.getTop()) <= viewU.getMeasuredWidth() / 2) ? iK : iK + 1 : iK + 1;
    }
}
