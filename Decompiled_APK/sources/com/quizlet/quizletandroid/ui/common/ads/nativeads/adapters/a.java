package com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.FrameLayout;
import androidx.compose.material3.C0676l1;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.V;
import com.google.android.gms.ads.k;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.L;
import com.quizlet.quizletandroid.ui.common.ads.nativeads.b;
import com.quizlet.quizletandroid.ui.common.ads.nativeads.module.c;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends V {
    public static final int d;
    public final c c;

    static {
        int i = b.b;
        d = R.layout.list_item_ad_view;
    }

    public a(AbstractC1361d0 abstractC1361d0, c cVar) {
        super(abstractC1361d0);
        this.c = cVar;
        cVar.e = new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 2);
        g();
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0022  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void g() {
        /*
            r6 = this;
            com.quizlet.quizletandroid.ui.common.ads.nativeads.module.c r0 = r6.c
            java.lang.Object r1 = r6.b
            androidx.recyclerview.widget.d0 r1 = (androidx.recyclerview.widget.AbstractC1361d0) r1
            int r1 = r1.getItemCount()
            com.quizlet.quizletandroid.ui.common.ads.nativeads.module.f r2 = r0.c
            androidx.compose.material3.l1 r0 = r0.b
            r3 = 0
            if (r1 <= 0) goto L22
            int r4 = r0.a
            int r5 = r4 + 1
            if (r1 >= r5) goto L18
            goto L22
        L18:
            int r0 = r0.b
            r5 = 1
            if (r0 != 0) goto L1e
            goto L23
        L1e:
            int r1 = r1 - r4
            int r1 = r1 / r0
            int r5 = r5 + r1
            goto L23
        L22:
            r5 = r3
        L23:
            monitor-enter(r2)
            int r0 = r2.i     // Catch: java.lang.Throwable -> L34
            r2.i = r5     // Catch: java.lang.Throwable -> L34
            if (r5 >= r0) goto L36
            int r0 = r2.c()     // Catch: java.lang.Throwable -> L34
            if (r5 >= r0) goto L36
            r2.d(r5)     // Catch: java.lang.Throwable -> L34
            goto L36
        L34:
            r0 = move-exception
            goto L3b
        L36:
            r2.e(r3)     // Catch: java.lang.Throwable -> L34
            monitor-exit(r2)
            return
        L3b:
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L34
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a.g():void");
    }

    @Override // androidx.recyclerview.widget.V, androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        int itemCount = ((AbstractC1361d0) this.b).getItemCount();
        c cVar = this.c;
        int iC = cVar.c.c();
        C0676l1 c0676l1 = cVar.b;
        int iMin = 0;
        if (iC > 0) {
            if (itemCount > 0) {
                int i = c0676l1.a;
                if (itemCount >= i + 1) {
                    int i2 = c0676l1.b;
                    iMin = 1;
                    if (i2 != 0) {
                        iMin = 1 + ((itemCount - i) / i2);
                    }
                }
            }
            iMin = Math.min(iC, iMin);
        }
        return iMin + itemCount;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final long getItemId(int i) {
        c cVar = this.c;
        if (!cVar.e(i)) {
            AbstractC1361d0 abstractC1361d0 = (AbstractC1361d0) this.b;
            return abstractC1361d0.getItemId(cVar.c(i, abstractC1361d0.getItemCount()));
        }
        int iA = cVar.b.a(i);
        if (iA >= 0) {
            return Long.MAX_VALUE - iA;
        }
        return -1L;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        c cVar = this.c;
        if (cVar.e(i)) {
            return d;
        }
        AbstractC1361d0 abstractC1361d0 = (AbstractC1361d0) this.b;
        return abstractC1361d0.getItemViewType(cVar.c(i, abstractC1361d0.getItemCount()));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        int itemViewType = f0.getItemViewType();
        int i2 = d;
        c cVar = this.c;
        if (itemViewType != i2) {
            AbstractC1361d0 abstractC1361d0 = (AbstractC1361d0) this.b;
            abstractC1361d0.onBindViewHolder(f0, cVar.c(i, abstractC1361d0.getItemCount()));
            return;
        }
        b bVar = (b) f0;
        k kVarA = cVar.e(i) ? cVar.a(i) : null;
        FrameLayout frameLayout = bVar.a.b;
        if (frameLayout.getChildCount() > 0) {
            frameLayout.removeAllViews();
        }
        frameLayout.setVisibility(kVarA != null ? 0 : 8);
        if (frameLayout.getVisibility() == 0) {
            if ((kVarA != null ? kVarA.getParent() : null) != null) {
                ViewParent parent = kVarA.getParent();
                Intrinsics.e(parent, "null cannot be cast to non-null type android.view.ViewGroup");
                ((ViewGroup) parent).removeView(kVarA);
            }
            frameLayout.addView(kVarA);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        if (i != d) {
            return ((AbstractC1361d0) this.b).onCreateViewHolder(parent, i);
        }
        int i2 = b.b;
        Intrinsics.checkNotNullParameter(parent, "parent");
        View viewInflate = LayoutInflater.from(parent.getContext()).inflate(R.layout.list_item_ad_view, parent, false);
        if (viewInflate == null) {
            throw new NullPointerException("rootView");
        }
        FrameLayout frameLayout = (FrameLayout) viewInflate;
        L l = new L(frameLayout, frameLayout, 0);
        Intrinsics.checkNotNullExpressionValue(l, "inflate(...)");
        return new b(l);
    }
}
