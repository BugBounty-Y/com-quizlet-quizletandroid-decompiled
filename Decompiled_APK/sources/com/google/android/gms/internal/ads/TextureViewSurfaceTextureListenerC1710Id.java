package com.google.android.gms.internal.ads;

import android.content.Context;
import android.graphics.SurfaceTexture;
import android.net.Uri;
import android.view.Surface;
import android.view.TextureView;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;

/* renamed from: com.google.android.gms.internal.ads.Id, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class TextureViewSurfaceTextureListenerC1710Id extends AbstractC2656td implements TextureView.SurfaceTextureListener, InterfaceC2828xd {
    public final C2743ve c;
    public final C1674Cd d;
    public final C1668Bd e;
    public final Hk f;
    public C2785wd g;
    public Surface h;
    public C2143he i;
    public String j;
    public String[] k;
    public boolean l;
    public int m;
    public C1662Ad n;
    public final boolean o;
    public boolean p;
    public boolean q;
    public int r;
    public int s;
    public float t;

    public TextureViewSurfaceTextureListenerC1710Id(Context context, C1674Cd c1674Cd, C2743ve c2743ve, boolean z, C1668Bd c1668Bd, Hk hk) {
        super(context);
        this.m = 1;
        this.c = c2743ve;
        this.d = c1674Cd;
        this.o = z;
        this.e = c1668Bd;
        c1674Cd.a(this);
        this.f = hk;
    }

    public static String E(String str, Exception exc) {
        return str + "/" + exc.getClass().getCanonicalName() + ":" + exc.getMessage();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final Integer A() {
        C2143he c2143he = this.i;
        if (c2143he != null) {
            return c2143he.q;
        }
        return null;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void B(int i) {
        C2143he c2143he = this.i;
        if (c2143he != null) {
            C1968de c1968de = c2143he.b;
            synchronized (c1968de) {
                c1968de.d = i * 1000;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void C(int i) {
        C2143he c2143he = this.i;
        if (c2143he != null) {
            C1968de c1968de = c2143he.b;
            synchronized (c1968de) {
                c1968de.e = i * 1000;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void D(int i) {
        C2143he c2143he = this.i;
        if (c2143he != null) {
            C1968de c1968de = c2143he.b;
            synchronized (c1968de) {
                c1968de.c = i * 1000;
            }
        }
    }

    public final void F() {
        if (this.p) {
            return;
        }
        this.p = true;
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC1692Fd(this, 7));
        m();
        C1674Cd c1674Cd = this.d;
        if (c1674Cd.i && !c1674Cd.j) {
            AbstractC2096gb.h(c1674Cd.e, c1674Cd.d, "vfr2");
            c1674Cd.j = true;
        }
        if (this.q) {
            u();
        }
    }

    public final void G(boolean z, Integer num) {
        AbstractC1794Wd abstractC1794Wd;
        C2143he c2143he = this.i;
        if (c2143he != null && !z) {
            c2143he.q = num;
            return;
        }
        if (this.j == null || this.h == null) {
            return;
        }
        if (z) {
            if (!K()) {
                com.google.android.gms.ads.internal.util.client.i.h("No valid ExoPlayerAdapter exists when switch source.");
                return;
            }
            PD pd = c2143he.g;
            pd.d.a();
            pd.c.c();
            H();
        }
        if (this.j.startsWith("cache:")) {
            C2743ve c2743ve = this.c;
            String str = this.j;
            ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = c2743ve.a;
            synchronized (viewTreeObserverOnGlobalLayoutListenerC2829xe) {
                HashMap map = viewTreeObserverOnGlobalLayoutListenerC2829xe.i1;
                if (map == null) {
                    abstractC1794Wd = null;
                } else {
                    abstractC1794Wd = (AbstractC1794Wd) map.get(str);
                }
            }
            if (abstractC1794Wd instanceof C1837ae) {
                C1837ae c1837ae = (C1837ae) abstractC1794Wd;
                synchronized (c1837ae) {
                    c1837ae.g = true;
                    c1837ae.notify();
                }
                C2143he c2143he2 = c1837ae.d;
                c2143he2.j = null;
                c1837ae.d = null;
                this.i = c2143he2;
                c2143he2.q = num;
                if (c2143he2.g == null) {
                    com.google.android.gms.ads.internal.util.client.i.h("Precached video player has been released.");
                    return;
                }
            } else {
                if (!(abstractC1794Wd instanceof C1812Zd)) {
                    com.google.android.gms.ads.internal.util.client.i.h("Stream cache miss: ".concat(String.valueOf(this.j)));
                    return;
                }
                C1812Zd c1812Zd = (C1812Zd) abstractC1794Wd;
                com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                C2743ve c2743ve2 = this.c;
                f.y(c2743ve2.getContext(), c2743ve2.a.e.a);
                synchronized (c1812Zd.k) {
                    try {
                        ByteBuffer byteBuffer = c1812Zd.i;
                        if (byteBuffer != null && !c1812Zd.j) {
                            byteBuffer.flip();
                            c1812Zd.j = true;
                        }
                        c1812Zd.f = true;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                ByteBuffer byteBuffer2 = c1812Zd.i;
                boolean z2 = c1812Zd.n;
                String str2 = c1812Zd.d;
                if (str2 == null) {
                    com.google.android.gms.ads.internal.util.client.i.h("Stream cache URL is null.");
                    return;
                }
                C2743ve c2743ve3 = this.c;
                C2143he c2143he3 = new C2143he(c2743ve3.getContext(), this.e, c2743ve3, num);
                com.google.android.gms.ads.internal.util.client.i.g("ExoPlayerAdapter initialized.");
                this.i = c2143he3;
                c2143he3.q(new Uri[]{Uri.parse(str2)}, byteBuffer2, z2);
            }
        } else {
            C2743ve c2743ve4 = this.c;
            C2143he c2143he4 = new C2143he(c2743ve4.getContext(), this.e, c2743ve4, num);
            com.google.android.gms.ads.internal.util.client.i.g("ExoPlayerAdapter initialized.");
            this.i = c2143he4;
            com.google.android.gms.ads.internal.util.F f2 = com.google.android.gms.ads.internal.j.C.c;
            C2743ve c2743ve5 = this.c;
            f2.y(c2743ve5.getContext(), c2743ve5.a.e.a);
            Uri[] uriArr = new Uri[this.k.length];
            int i = 0;
            while (true) {
                String[] strArr = this.k;
                if (i >= strArr.length) {
                    break;
                }
                uriArr[i] = Uri.parse(strArr[i]);
                i++;
            }
            C2143he c2143he5 = this.i;
            c2143he5.getClass();
            c2143he5.q(uriArr, ByteBuffer.allocate(0), false);
        }
        this.i.j = this;
        I(this.h);
        PD pd2 = this.i.g;
        if (pd2 != null) {
            int iH = pd2.h();
            this.m = iH;
            if (iH == 3) {
                F();
            }
        }
    }

    public final void H() {
        if (this.i != null) {
            I(null);
            C2143he c2143he = this.i;
            if (c2143he != null) {
                c2143he.j = null;
                PD pd = c2143he.g;
                if (pd != null) {
                    pd.d.a();
                    pd.c.l1(c2143he);
                    PD pd2 = c2143he.g;
                    pd2.d.a();
                    pd2.c.k1();
                    c2143he.g = null;
                    C2143he.v.decrementAndGet();
                }
                this.i = null;
            }
            this.m = 1;
            this.l = false;
            this.p = false;
            this.q = false;
        }
    }

    public final void I(Surface surface) {
        C2143he c2143he = this.i;
        if (c2143he == null) {
            com.google.android.gms.ads.internal.util.client.i.h("Trying to set surface before player is initialized.");
            return;
        }
        try {
            PD pd = c2143he.g;
            if (pd != null) {
                pd.d.a();
                C2221jD c2221jD = pd.c;
                c2221jD.U();
                c2221jD.v1(surface);
                int i = surface == null ? 0 : -1;
                c2221jD.t1(i, i);
            }
        } catch (IOException e) {
            com.google.android.gms.ads.internal.util.client.i.i("", e);
        }
    }

    public final boolean J() {
        return K() && this.m != 1;
    }

    public final boolean K() {
        C2143he c2143he = this.i;
        return (c2143he == null || c2143he.g == null || this.l) ? false : true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2828xd
    public final void a(int i) {
        C2143he c2143he;
        if (this.m != i) {
            this.m = i;
            if (i == 3) {
                F();
                return;
            }
            if (i != 4) {
                return;
            }
            if (this.e.a && (c2143he = this.i) != null) {
                c2143he.r(false);
            }
            this.d.m = false;
            C1686Ed c1686Ed = this.b;
            c1686Ed.d = false;
            c1686Ed.a();
            com.google.android.gms.ads.internal.util.F.l.post(new RunnableC1692Fd(this, 6));
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void b(int i) {
        C2143he c2143he = this.i;
        if (c2143he != null) {
            C1968de c1968de = c2143he.b;
            synchronized (c1968de) {
                c1968de.b = i * 1000;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void c(int i) throws SocketException {
        C2143he c2143he = this.i;
        if (c2143he != null) {
            Iterator it2 = c2143he.t.iterator();
            while (it2.hasNext()) {
                C1924ce c1924ce = (C1924ce) ((WeakReference) it2.next()).get();
                if (c1924ce != null) {
                    c1924ce.r = i;
                    Iterator it3 = c1924ce.s.iterator();
                    while (it3.hasNext()) {
                        Socket socket = (Socket) it3.next();
                        if (!socket.isClosed()) {
                            try {
                                socket.setReceiveBufferSize(c1924ce.r);
                            } catch (SocketException e) {
                                com.google.android.gms.ads.internal.util.client.i.i("Failed to update receive buffer size.", e);
                            }
                        }
                    }
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2828xd
    public final void d() {
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC1692Fd(this, 0));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2828xd
    public final void e(long j, boolean z) {
        if (this.c != null) {
            AbstractC2270kd.f.execute(new RunnableC1698Gd(this, z, j, 0));
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void f(String str, String[] strArr, Integer num) {
        if (str == null) {
            return;
        }
        if (strArr == null) {
            this.k = new String[]{str};
        } else {
            this.k = (String[]) Arrays.copyOf(strArr, strArr.length);
        }
        String str2 = this.j;
        boolean z = false;
        if (this.e.k && str2 != null && !str.equals(str2) && this.m == 4) {
            z = true;
        }
        this.j = str;
        G(z, num);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2828xd
    public final void g(IOException iOException) {
        String strE = E("onLoadException", iOException);
        com.google.android.gms.ads.internal.util.client.i.h("ExoPlayerAdapter exception: ".concat(strE));
        com.google.android.gms.ads.internal.j.C.h.g("AdExoPlayerView.onException", iOException);
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC1704Hd(this, strE, 0));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2828xd
    public final void h(String str, Exception exc) {
        C2143he c2143he;
        String strE = E(str, exc);
        com.google.android.gms.ads.internal.util.client.i.h("ExoPlayerAdapter error: ".concat(strE));
        this.l = true;
        if (this.e.a && (c2143he = this.i) != null) {
            c2143he.r(false);
        }
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC1704Hd(this, strE, 1));
        com.google.android.gms.ads.internal.j.C.h.g("AdExoPlayerView.onError", exc);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2828xd
    public final void i(int i, int i2) {
        this.r = i;
        this.s = i2;
        float f = i2 > 0 ? i / i2 : 1.0f;
        if (this.t != f) {
            this.t = f;
            requestLayout();
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int j() {
        if (J()) {
            return (int) this.i.g.n1();
        }
        return 0;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int k() {
        C2143he c2143he = this.i;
        if (c2143he != null) {
            return c2143he.l;
        }
        return -1;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int l() {
        if (J()) {
            return (int) this.i.g.o1();
        }
        return 0;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1680Dd
    public final void m() {
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC1692Fd(this, 2));
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int n() {
        return this.s;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int o() {
        return this.r;
    }

    @Override // android.view.TextureView, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        setSurfaceTextureListener(this);
    }

    @Override // android.view.View
    public final void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
        int measuredWidth = getMeasuredWidth();
        int measuredHeight = getMeasuredHeight();
        float f = this.t;
        if (f != DefinitionKt.NO_Float_VALUE && this.n == null) {
            float f2 = measuredWidth;
            float f3 = f2 / measuredHeight;
            if (f > f3) {
                measuredHeight = (int) (f2 / f);
            }
            if (f < f3) {
                measuredWidth = (int) (measuredHeight * f);
            }
        }
        setMeasuredDimension(measuredWidth, measuredHeight);
        C1662Ad c1662Ad = this.n;
        if (c1662Ad != null) {
            c1662Ad.a(measuredWidth, measuredHeight);
        }
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public final void onSurfaceTextureAvailable(SurfaceTexture surfaceTexture, int i, int i2) throws InterruptedException {
        C2143he c2143he;
        float f;
        int i3;
        SurfaceTexture surfaceTexture2;
        Hk hk;
        if (this.o) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.hd)).booleanValue() && (hk = this.f) != null) {
                Fi fiA = hk.a();
                fiA.o("action", "svp_aepv");
                fiA.x();
            }
            C1662Ad c1662Ad = new C1662Ad(getContext());
            this.n = c1662Ad;
            c1662Ad.m = i;
            c1662Ad.l = i2;
            c1662Ad.o = surfaceTexture;
            c1662Ad.start();
            if (c1662Ad.o == null) {
                surfaceTexture2 = null;
            } else {
                try {
                    c1662Ad.t.await();
                } catch (InterruptedException unused) {
                }
                surfaceTexture2 = c1662Ad.n;
            }
            if (surfaceTexture2 != null) {
                surfaceTexture = surfaceTexture2;
            } else {
                this.n.b();
                this.n = null;
            }
        }
        Surface surface = new Surface(surfaceTexture);
        this.h = surface;
        if (this.i == null) {
            G(false, null);
        } else {
            I(surface);
            if (!this.e.a && (c2143he = this.i) != null) {
                c2143he.r(true);
            }
        }
        int i4 = this.r;
        if (i4 == 0 || (i3 = this.s) == 0) {
            f = i2 > 0 ? i / i2 : 1.0f;
            if (this.t != f) {
                this.t = f;
                requestLayout();
            }
        } else {
            f = i3 > 0 ? i4 / i3 : 1.0f;
            if (this.t != f) {
                this.t = f;
                requestLayout();
            }
        }
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC1692Fd(this, 5));
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public final boolean onSurfaceTextureDestroyed(SurfaceTexture surfaceTexture) {
        t();
        C1662Ad c1662Ad = this.n;
        if (c1662Ad != null) {
            c1662Ad.b();
            this.n = null;
        }
        C2143he c2143he = this.i;
        if (c2143he != null) {
            if (c2143he != null) {
                c2143he.r(false);
            }
            Surface surface = this.h;
            if (surface != null) {
                surface.release();
            }
            this.h = null;
            I(null);
        }
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC1692Fd(this, 3));
        return true;
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public final void onSurfaceTextureSizeChanged(SurfaceTexture surfaceTexture, int i, int i2) {
        C1662Ad c1662Ad = this.n;
        if (c1662Ad != null) {
            c1662Ad.a(i, i2);
        }
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2570rd(this, i, i2, 1));
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public final void onSurfaceTextureUpdated(SurfaceTexture surfaceTexture) {
        this.d.d(this);
        this.a.b(surfaceTexture, this.g);
    }

    @Override // android.view.View
    public final void onWindowVisibilityChanged(int i) {
        com.google.android.gms.ads.internal.util.A.l("AdExoPlayerView3 window visibility changed to " + i);
        com.google.android.gms.ads.internal.util.F.l.post(new androidx.core.provider.a(this, i, 7));
        super.onWindowVisibilityChanged(i);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final long p() {
        C2143he c2143he = this.i;
        if (c2143he != null) {
            return c2143he.u();
        }
        return -1L;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final long q() {
        C2143he c2143he = this.i;
        if (c2143he == null) {
            return -1L;
        }
        if (c2143he.s == null || !c2143he.s.o) {
            return c2143he.k;
        }
        return 0L;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final long r() {
        C2143he c2143he = this.i;
        if (c2143he != null) {
            return c2143he.p();
        }
        return -1L;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final String s() {
        return "ExoPlayer/2".concat(true != this.o ? "" : " spherical");
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void t() {
        C2143he c2143he;
        if (J()) {
            if (this.e.a && (c2143he = this.i) != null) {
                c2143he.r(false);
            }
            PD pd = this.i.g;
            pd.d.a();
            pd.c.A1(false);
            this.d.m = false;
            C1686Ed c1686Ed = this.b;
            c1686Ed.d = false;
            c1686Ed.a();
            com.google.android.gms.ads.internal.util.F.l.post(new RunnableC1692Fd(this, 4));
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void u() {
        C2143he c2143he;
        if (!J()) {
            this.q = true;
            return;
        }
        if (this.e.a && (c2143he = this.i) != null) {
            c2143he.r(true);
        }
        PD pd = this.i.g;
        pd.d.a();
        pd.c.A1(true);
        this.d.b();
        C1686Ed c1686Ed = this.b;
        c1686Ed.d = true;
        c1686Ed.a();
        this.a.c = true;
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC1692Fd(this, 1));
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void v(int i) {
        if (J()) {
            long j = i;
            PD pd = this.i.g;
            pd.X0(pd.a1(), j);
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void w(C2785wd c2785wd) {
        this.g = c2785wd;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void x(String str) {
        if (str != null) {
            f(str, null, null);
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void y() {
        if (K()) {
            PD pd = this.i.g;
            pd.d.a();
            pd.c.c();
            H();
        }
        C1674Cd c1674Cd = this.d;
        c1674Cd.m = false;
        C1686Ed c1686Ed = this.b;
        c1686Ed.d = false;
        c1686Ed.a();
        c1674Cd.c();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void z(float f, float f2) {
        C1662Ad c1662Ad = this.n;
        if (c1662Ad != null) {
            c1662Ad.c(f, f2);
        }
    }
}
