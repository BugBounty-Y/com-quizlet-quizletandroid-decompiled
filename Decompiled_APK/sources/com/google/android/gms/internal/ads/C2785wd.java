package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import com.quizlet.quizletandroid.R;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.wd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2785wd extends FrameLayout {
    public final C2743ve a;
    public final FrameLayout b;
    public final View c;
    public final B7 d;
    public final RunnableC2742vd e;
    public final long f;
    public final AbstractC2656td g;
    public boolean h;
    public boolean i;
    public boolean j;
    public boolean k;
    public long l;
    public long m;
    public String n;
    public String[] o;
    public Bitmap p;
    public final ImageView q;
    public boolean r;

    public C2785wd(Context context, C2743ve c2743ve, int i, boolean z, B7 b7, C1668Bd c1668Bd, Hk hk) {
        B7 b72;
        AbstractC2656td textureViewSurfaceTextureListenerC2613sd;
        AbstractC2656td c2314le;
        super(context);
        this.a = c2743ve;
        this.d = b7;
        FrameLayout frameLayout = new FrameLayout(context);
        this.b = frameLayout;
        addView(frameLayout, new FrameLayout.LayoutParams(-1, -1));
        com.google.android.gms.common.internal.u.h(c2743ve.a.g);
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = c2743ve.a;
        Object obj = viewTreeObserverOnGlobalLayoutListenerC2829xe.g.b;
        C1674Cd c1674Cd = new C1674Cd(context, viewTreeObserverOnGlobalLayoutListenerC2829xe.e, viewTreeObserverOnGlobalLayoutListenerC2829xe.C0(), b7, viewTreeObserverOnGlobalLayoutListenerC2829xe.J);
        if (i == 3) {
            c2314le = new C2314le(context, c1674Cd);
            b72 = b7;
        } else {
            if (i == 2) {
                viewTreeObserverOnGlobalLayoutListenerC2829xe.O().getClass();
                textureViewSurfaceTextureListenerC2613sd = new TextureViewSurfaceTextureListenerC1710Id(context, c1674Cd, c2743ve, z, c1668Bd, hk);
                b72 = b7;
            } else {
                b72 = b7;
                textureViewSurfaceTextureListenerC2613sd = new TextureViewSurfaceTextureListenerC2613sd(context, c2743ve, z, viewTreeObserverOnGlobalLayoutListenerC2829xe.O().b(), new C1674Cd(context, viewTreeObserverOnGlobalLayoutListenerC2829xe.e, viewTreeObserverOnGlobalLayoutListenerC2829xe.C0(), b7, viewTreeObserverOnGlobalLayoutListenerC2829xe.J), hk);
            }
            c2314le = textureViewSurfaceTextureListenerC2613sd;
        }
        this.g = c2314le;
        View view = new View(context);
        this.c = view;
        view.setBackgroundColor(0);
        frameLayout.addView(c2314le, new FrameLayout.LayoutParams(-1, -1, 17));
        C2601s7 c2601s7 = AbstractC2773w7.M;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            frameLayout.addView(view, new FrameLayout.LayoutParams(-1, -1));
            frameLayout.bringChildToFront(view);
        }
        if (((Boolean) rVar.c.a(AbstractC2773w7.J)).booleanValue()) {
            k();
        }
        this.q = new ImageView(context);
        this.f = ((Long) rVar.c.a(AbstractC2773w7.O)).longValue();
        boolean zBooleanValue = ((Boolean) rVar.c.a(AbstractC2773w7.L)).booleanValue();
        this.k = zBooleanValue;
        b72.b("spinner_used", true != zBooleanValue ? "0" : "1");
        this.e = new RunnableC2742vd(this);
        c2314le.w(this);
    }

    public final void a(int i, int i2, int i3, int i4) {
        if (com.google.android.gms.ads.internal.util.A.m()) {
            StringBuilder sbW = android.support.v4.media.session.a.w("Set video bounds to x:", i, ";y:", ";w:", i2);
            sbW.append(i3);
            sbW.append(";h:");
            sbW.append(i4);
            com.google.android.gms.ads.internal.util.A.l(sbW.toString());
        }
        if (i3 == 0 || i4 == 0) {
            return;
        }
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(i3, i4);
        layoutParams.setMargins(i, i2, 0, 0);
        this.b.setLayoutParams(layoutParams);
        requestLayout();
    }

    public final void b() {
        C2743ve c2743ve = this.a;
        if (c2743ve.zzi() == null || !this.i || this.j) {
            return;
        }
        c2743ve.zzi().getWindow().clearFlags(128);
        this.i = false;
    }

    public final void c(String str, String... strArr) {
        HashMap map = new HashMap();
        AbstractC2656td abstractC2656td = this.g;
        Integer numA = abstractC2656td != null ? abstractC2656td.A() : null;
        if (numA != null) {
            map.put("playerId", numA.toString());
        }
        map.put("event", str);
        String str2 = null;
        for (String str3 : strArr) {
            if (str2 == null) {
                str2 = str3;
            } else {
                map.put(str2, str3);
                str2 = null;
            }
        }
        this.a.j("onVideoEvent", map);
    }

    public final void d() {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.V1)).booleanValue()) {
            this.e.a();
        }
        c("ended", new String[0]);
        b();
    }

    public final void e() {
        c("pause", new String[0]);
        b();
        this.h = false;
    }

    public final void f() {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.V1)).booleanValue()) {
            RunnableC2742vd runnableC2742vd = this.e;
            runnableC2742vd.b = false;
            com.google.android.gms.ads.internal.util.B b = com.google.android.gms.ads.internal.util.F.l;
            b.removeCallbacks(runnableC2742vd);
            b.postDelayed(runnableC2742vd, 250L);
        }
        C2743ve c2743ve = this.a;
        if (c2743ve.zzi() != null && !this.i) {
            boolean z = (c2743ve.zzi().getWindow().getAttributes().flags & 128) != 0;
            this.j = z;
            if (!z) {
                c2743ve.zzi().getWindow().addFlags(128);
                this.i = true;
            }
        }
        this.h = true;
    }

    public final void finalize() throws Throwable {
        try {
            this.e.a();
            AbstractC2656td abstractC2656td = this.g;
            if (abstractC2656td != null) {
                AbstractC2270kd.f.execute(new RunnableC1989e(abstractC2656td, 16));
            }
        } finally {
            super.finalize();
        }
    }

    public final void g() {
        AbstractC2656td abstractC2656td = this.g;
        if (abstractC2656td != null && this.m == 0) {
            c("canplaythrough", "duration", String.valueOf(abstractC2656td.l() / 1000.0f), "videoWidth", String.valueOf(abstractC2656td.o()), "videoHeight", String.valueOf(abstractC2656td.n()));
        }
    }

    public final void h() {
        this.c.setVisibility(4);
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2699ud(this, 0));
    }

    public final void i() {
        if (this.r && this.p != null) {
            ImageView imageView = this.q;
            if (imageView.getParent() == null) {
                imageView.setImageBitmap(this.p);
                imageView.invalidate();
                FrameLayout frameLayout = this.b;
                frameLayout.addView(imageView, new FrameLayout.LayoutParams(-1, -1));
                frameLayout.bringChildToFront(imageView);
            }
        }
        this.e.a();
        this.m = this.l;
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2699ud(this, 2));
    }

    public final void j(int i, int i2) {
        if (this.k) {
            C2601s7 c2601s7 = AbstractC2773w7.N;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            int iMax = Math.max(i / ((Integer) rVar.c.a(c2601s7)).intValue(), 1);
            int iMax2 = Math.max(i2 / ((Integer) rVar.c.a(c2601s7)).intValue(), 1);
            Bitmap bitmap = this.p;
            if (bitmap != null && bitmap.getWidth() == iMax && this.p.getHeight() == iMax2) {
                return;
            }
            this.p = Bitmap.createBitmap(iMax, iMax2, Bitmap.Config.ARGB_8888);
            this.r = false;
        }
    }

    public final void k() {
        AbstractC2656td abstractC2656td = this.g;
        if (abstractC2656td == null) {
            return;
        }
        TextView textView = new TextView(abstractC2656td.getContext());
        Resources resourcesB = com.google.android.gms.ads.internal.j.C.h.b();
        textView.setText(String.valueOf(resourcesB == null ? "AdMob - " : resourcesB.getString(R.string.watermark_label_prefix)).concat(abstractC2656td.s()));
        textView.setTextColor(-65536);
        textView.setBackgroundColor(-256);
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-2, -2, 17);
        FrameLayout frameLayout = this.b;
        frameLayout.addView(textView, layoutParams);
        frameLayout.bringChildToFront(textView);
    }

    public final void l() {
        AbstractC2656td abstractC2656td = this.g;
        if (abstractC2656td == null) {
            return;
        }
        long j = abstractC2656td.j();
        if (this.l == j || j <= 0) {
            return;
        }
        float f = j / 1000.0f;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T1)).booleanValue()) {
            String strValueOf = String.valueOf(f);
            String strValueOf2 = String.valueOf(abstractC2656td.r());
            String strValueOf3 = String.valueOf(abstractC2656td.p());
            String strValueOf4 = String.valueOf(abstractC2656td.q());
            String strValueOf5 = String.valueOf(abstractC2656td.k());
            com.google.android.gms.ads.internal.j.C.k.getClass();
            c("timeupdate", "time", strValueOf, "totalBytes", strValueOf2, "qoeCachedBytes", strValueOf3, "qoeLoadedBytes", strValueOf4, "droppedFrames", strValueOf5, "reportTime", String.valueOf(System.currentTimeMillis()));
        } else {
            c("timeupdate", "time", String.valueOf(f));
        }
        this.l = j;
    }

    @Override // android.view.View
    public final void onWindowFocusChanged(boolean z) {
        super.onWindowFocusChanged(z);
        RunnableC2742vd runnableC2742vd = this.e;
        if (z) {
            runnableC2742vd.b = false;
            com.google.android.gms.ads.internal.util.B b = com.google.android.gms.ads.internal.util.F.l;
            b.removeCallbacks(runnableC2742vd);
            b.postDelayed(runnableC2742vd, 250L);
        } else {
            runnableC2742vd.a();
            this.m = this.l;
        }
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2742vd(this, z, 0));
    }

    @Override // android.view.View
    public final void onWindowVisibilityChanged(int i) {
        super.onWindowVisibilityChanged(i);
        boolean z = false;
        RunnableC2742vd runnableC2742vd = this.e;
        if (i == 0) {
            runnableC2742vd.b = false;
            com.google.android.gms.ads.internal.util.B b = com.google.android.gms.ads.internal.util.F.l;
            b.removeCallbacks(runnableC2742vd);
            b.postDelayed(runnableC2742vd, 250L);
            z = true;
        } else {
            runnableC2742vd.a();
            this.m = this.l;
        }
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2742vd(this, z, 1));
    }
}
