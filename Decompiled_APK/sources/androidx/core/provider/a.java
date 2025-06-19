package androidx.core.provider;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import androidx.viewpager2.widget.l;
import com.google.android.gms.common.api.internal.n;
import com.google.android.gms.internal.ads.AbstractC2457os;
import com.google.android.gms.internal.ads.C2047fD;
import com.google.android.gms.internal.ads.C2384n4;
import com.google.android.gms.internal.ads.C2436oD;
import com.google.android.gms.internal.ads.C2785wd;
import com.google.android.gms.internal.ads.F7;
import com.google.android.gms.internal.ads.Fi;
import com.google.android.gms.internal.ads.Hk;
import com.google.android.gms.internal.ads.JE;
import com.google.android.gms.internal.ads.TextureViewSurfaceTextureListenerC1710Id;
import com.google.android.gms.internal.ads.TextureViewSurfaceTextureListenerC2613sd;
import com.google.android.gms.internal.ads.WD;
import com.google.android.gms.internal.ads.Z4;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.quizlet.features.setpage.r;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a implements Runnable {
    public final /* synthetic */ int a;
    public final int b;
    public final Object c;

    public /* synthetic */ a(C2436oD c2436oD, int i, boolean z) {
        this.a = 8;
        this.c = c2436oD;
        this.b = i;
    }

    @Override // java.lang.Runnable
    public final void run() throws InterruptedException {
        C2384n4 c2384n4C;
        switch (this.a) {
            case 0:
                androidx.core.content.res.b bVar = (androidx.core.content.res.b) ((com.airbnb.lottie.network.c) this.c).b;
                if (bVar != null) {
                    bVar.i(this.b);
                    return;
                }
                return;
            case 1:
                ArrayList arrayList = (ArrayList) this.c;
                int size = arrayList.size();
                int i = 0;
                if (this.b != 1) {
                    while (i < size) {
                        ((androidx.emoji2.text.h) arrayList.get(i)).a();
                        i++;
                    }
                    return;
                } else {
                    while (i < size) {
                        ((androidx.emoji2.text.h) arrayList.get(i)).b();
                        i++;
                    }
                    return;
                }
            case 2:
                ((l) this.c).n0(this.b);
                return;
            case 3:
                ((n) this.c).b(this.b);
                return;
            case 4:
                int i2 = this.b;
                Z4 z4 = (Z4) this.c;
                if (i2 > 0) {
                    try {
                        Thread.sleep(i2 * 1000);
                    } catch (InterruptedException unused) {
                    }
                }
                try {
                    Context context = z4.a;
                    c2384n4C = AbstractC2457os.c(context, context.getPackageName(), Integer.toString(context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionCode));
                } catch (Throwable unused2) {
                    c2384n4C = null;
                }
                Z4 z42 = (Z4) this.c;
                z42.h = c2384n4C;
                int i3 = this.b;
                if (i3 < 4) {
                    if (c2384n4C != null && c2384n4C.c0() && !c2384n4C.n0().equals("0000000000000000000000000000000000000000000000000000000000000000") && c2384n4C.d0() && c2384n4C.m0().A() && c2384n4C.m0().w() != -2) {
                        return;
                    }
                    int i4 = i3 + 1;
                    if (z42.l) {
                        Future<?> futureSubmit = z42.b.submit(new a(z42, i4, 4));
                        if (i4 == 0) {
                            z42.i = futureSubmit;
                            return;
                        }
                        return;
                    }
                    return;
                }
                return;
            case 5:
                Hk hk = ((F7) this.c).d;
                if (hk != null) {
                    Fi fiA = hk.a();
                    fiA.o("action", "cct_nav");
                    fiA.o("cct_navs", String.valueOf(this.b));
                    fiA.x();
                    return;
                }
                return;
            case 6:
                C2785wd c2785wd = ((TextureViewSurfaceTextureListenerC2613sd) this.c).q;
                if (c2785wd != null) {
                    c2785wd.onWindowVisibilityChanged(this.b);
                    return;
                }
                return;
            case 7:
                C2785wd c2785wd2 = ((TextureViewSurfaceTextureListenerC1710Id) this.c).g;
                if (c2785wd2 != null) {
                    c2785wd2.onWindowVisibilityChanged(this.b);
                    return;
                }
                return;
            case 8:
                C2436oD c2436oD = (C2436oD) this.c;
                int i5 = ((JE) c2436oD.a[this.b].e).b;
                WD wd = c2436oD.u;
                wd.i(wd.l(), 1033, new C2047fD(27));
                return;
            case 9:
                ((com.google.android.material.datepicker.k) this.c).h.n0(this.b);
                return;
            default:
                r rVar = (r) this.c;
                Object value = rVar.p.getValue();
                Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
                ((View) value).setVisibility(0);
                rVar.T().setVisibility(0);
                ViewGroup viewGroupO = rVar.O();
                ViewGroup.LayoutParams layoutParams = viewGroupO.getLayoutParams();
                if (layoutParams == null) {
                    throw new NullPointerException("null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
                }
                ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
                marginLayoutParams.bottomMargin = this.b;
                viewGroupO.setLayoutParams(marginLayoutParams);
                return;
        }
    }

    public /* synthetic */ a(Object obj, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.b = i;
    }

    public a(int i, l lVar) {
        this.a = 2;
        this.b = i;
        this.c = lVar;
    }

    public a(List list, int i, Throwable th) {
        this.a = 1;
        AbstractC3242q6.g(list, "initCallbacks cannot be null");
        this.c = new ArrayList(list);
        this.b = i;
    }
}
