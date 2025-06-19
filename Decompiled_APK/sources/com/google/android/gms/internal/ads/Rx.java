package com.google.android.gms.internal.ads;

import android.content.Context;
import android.net.Uri;
import android.text.TextUtils;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class Rx implements Fw {
    public final Context a;
    public final ArrayList b = new ArrayList();
    public final C2807wz c;
    public C2000eA d;
    public C2201iu e;
    public Rv f;
    public Fw g;
    public KC h;
    public C2203iw i;
    public C2046fC j;
    public Fw k;

    public Rx(Context context, C2807wz c2807wz) {
        this.a = context.getApplicationContext();
        this.c = c2807wz;
    }

    public static final void n(Fw fw, FC fc) {
        if (fw != null) {
            fw.m(fc);
        }
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Uri a() {
        Fw fw = this.k;
        if (fw == null) {
            return null;
        }
        return fw.a();
    }

    public final void b(Fw fw) {
        int i = 0;
        while (true) {
            ArrayList arrayList = this.b;
            if (i >= arrayList.size()) {
                return;
            }
            fw.m((FC) arrayList.get(i));
            i++;
        }
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final long c(C2891yx c2891yx) {
        AbstractC1795We.L(this.k == null);
        Uri uri = c2891yx.a;
        String scheme = uri.getScheme();
        String str = Yo.a;
        String scheme2 = uri.getScheme();
        boolean zIsEmpty = TextUtils.isEmpty(scheme2);
        Context context = this.a;
        if (zIsEmpty || Objects.equals(scheme2, "file")) {
            String path = uri.getPath();
            if (path == null || !path.startsWith("/android_asset/")) {
                if (this.d == null) {
                    C2000eA c2000eA = new C2000eA(false);
                    this.d = c2000eA;
                    b(c2000eA);
                }
                this.k = this.d;
            } else {
                if (this.e == null) {
                    C2201iu c2201iu = new C2201iu(context);
                    this.e = c2201iu;
                    b(c2201iu);
                }
                this.k = this.e;
            }
        } else if ("asset".equals(scheme)) {
            if (this.e == null) {
                C2201iu c2201iu2 = new C2201iu(context);
                this.e = c2201iu2;
                b(c2201iu2);
            }
            this.k = this.e;
        } else if ("content".equals(scheme)) {
            if (this.f == null) {
                Rv rv = new Rv(context);
                this.f = rv;
                b(rv);
            }
            this.k = this.f;
        } else {
            boolean zEquals = "rtmp".equals(scheme);
            C2807wz c2807wz = this.c;
            if (zEquals) {
                if (this.g == null) {
                    try {
                        Fw fw = (Fw) Class.forName("androidx.media3.datasource.rtmp.RtmpDataSource").getConstructor(null).newInstance(null);
                        this.g = fw;
                        b(fw);
                    } catch (ClassNotFoundException unused) {
                        AbstractC2096gb.J("DefaultDataSource", "Attempting to play RTMP stream without depending on the RTMP extension");
                    } catch (Exception e) {
                        throw new RuntimeException("Error instantiating RTMP extension", e);
                    }
                    if (this.g == null) {
                        this.g = c2807wz;
                    }
                }
                this.k = this.g;
            } else if ("udp".equals(scheme)) {
                if (this.h == null) {
                    KC kc = new KC();
                    this.h = kc;
                    b(kc);
                }
                this.k = this.h;
            } else if ("data".equals(scheme)) {
                if (this.i == null) {
                    C2203iw c2203iw = new C2203iw(false);
                    this.i = c2203iw;
                    b(c2203iw);
                }
                this.k = this.i;
            } else if ("rawresource".equals(scheme) || "android.resource".equals(scheme)) {
                if (this.j == null) {
                    C2046fC c2046fC = new C2046fC(context);
                    this.j = c2046fC;
                    b(c2046fC);
                }
                this.k = this.j;
            } else {
                this.k = c2807wz;
            }
        }
        return this.k.c(c2891yx);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    public final int d(int i, byte[] bArr, int i2) {
        Fw fw = this.k;
        fw.getClass();
        return fw.d(i, bArr, i2);
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void j() {
        Fw fw = this.k;
        if (fw != null) {
            try {
                fw.j();
            } finally {
                this.k = null;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void m(FC fc) {
        fc.getClass();
        this.c.m(fc);
        this.b.add(fc);
        n(this.d, fc);
        n(this.e, fc);
        n(this.f, fc);
        n(this.g, fc);
        n(this.h, fc);
        n(this.i, fc);
        n(this.j, fc);
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Map zze() {
        Fw fw = this.k;
        return fw == null ? Collections.EMPTY_MAP : fw.zze();
    }
}
