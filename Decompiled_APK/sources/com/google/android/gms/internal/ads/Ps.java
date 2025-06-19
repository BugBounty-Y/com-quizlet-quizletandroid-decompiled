package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.SharedPreferences;
import android.media.LoudnessCodecController;
import android.media.MediaCodec;
import android.media.MediaFormat;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.Surface;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

/* loaded from: classes2.dex */
public final class Ps implements InterfaceC1844al, GE {
    public static Ps c;
    public Object a;
    public Object b;

    public Ps(C1832aG c1832aG, String str) {
        this.b = c1832aG;
        this.a = str;
    }

    @Override // com.google.android.gms.internal.ads.GE
    public MediaFormat a() {
        return ((MediaCodec) this.a).getOutputFormat();
    }

    public void b(C2163hy c2163hy) throws GeneralSecurityException {
        if (c2163hy == null) {
            throw new NullPointerException("primitive constructor must be non-null");
        }
        C2248jy c2248jy = new C2248jy(c2163hy.a, c2163hy.b);
        HashMap map = (HashMap) this.a;
        if (!map.containsKey(c2248jy)) {
            map.put(c2248jy, c2163hy);
            return;
        }
        C2163hy c2163hy2 = (C2163hy) map.get(c2248jy);
        if (!c2163hy2.equals(c2163hy) || !c2163hy.equals(c2163hy2)) {
            throw new GeneralSecurityException("Attempt to register non-equal PrimitiveConstructor object for already existing object of type: ".concat(c2248jy.toString()));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1844al
    public void c(Object obj, C2049fF c2049fF) {
        ((SD) obj).j((PD) this.b, new Fp(c2049fF, ((WD) this.a).e));
    }

    @Override // com.google.android.gms.internal.ads.GE
    public ByteBuffer d(int i) {
        return ((MediaCodec) this.a).getInputBuffer(i);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public ByteBuffer e(int i) {
        return ((MediaCodec) this.a).getOutputBuffer(i);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void f(Surface surface) {
        ((MediaCodec) this.a).setOutputSurface(surface);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public /* synthetic */ boolean g(Lr lr) {
        return false;
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void h(int i, long j) {
        ((MediaCodec) this.a).releaseOutputBuffer(i, j);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void i() {
        ((MediaCodec) this.a).flush();
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void j(int i) {
        ((MediaCodec) this.a).setVideoScalingMode(i);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public int k(MediaCodec.BufferInfo bufferInfo) {
        int iDequeueOutputBuffer;
        do {
            iDequeueOutputBuffer = ((MediaCodec) this.a).dequeueOutputBuffer(bufferInfo, 0L);
        } while (iDequeueOutputBuffer == -3);
        return iDequeueOutputBuffer;
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void l() {
        Fp fp = (Fp) this.b;
        MediaCodec mediaCodec = (MediaCodec) this.a;
        try {
            int i = Build.VERSION.SDK_INT;
            if (i >= 30 && i < 33) {
                mediaCodec.stop();
            }
            if (i >= 35 && fp != null) {
                fp.f(mediaCodec);
            }
            mediaCodec.release();
        } catch (Throwable th) {
            if (Build.VERSION.SDK_INT >= 35 && fp != null) {
                fp.f(mediaCodec);
            }
            mediaCodec.release();
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void m(int i) {
        ((MediaCodec) this.a).releaseOutputBuffer(i, false);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void n(long j, int i, int i2, int i3) throws MediaCodec.CryptoException {
        ((MediaCodec) this.a).queueInputBuffer(i, 0, i2, j, i3);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void o(Bundle bundle) {
        ((MediaCodec) this.a).setParameters(bundle);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void p(int i, LC lc, long j) throws MediaCodec.CryptoException {
        ((MediaCodec) this.a).queueSecureInputBuffer(i, 0, lc.i, j, 0);
    }

    public void q(HC hc) {
        ((List) this.b).add(hc);
    }

    public void r(InterfaceC2334ly interfaceC2334ly) throws GeneralSecurityException {
        Class clsZzb = interfaceC2334ly.zzb();
        HashMap map = (HashMap) this.b;
        if (!map.containsKey(clsZzb)) {
            map.put(clsZzb, interfaceC2334ly);
            return;
        }
        InterfaceC2334ly interfaceC2334ly2 = (InterfaceC2334ly) map.get(clsZzb);
        if (!interfaceC2334ly2.equals(interfaceC2334ly) || !interfaceC2334ly.equals(interfaceC2334ly2)) {
            throw new GeneralSecurityException("Attempt to register non-equal PrimitiveWrapper object or input class object for already existing object of type".concat(clsZzb.toString()));
        }
    }

    public void s(HC hc) {
        ((List) this.a).add(hc);
    }

    public IC t() {
        return new IC((List) this.a, (List) this.b);
    }

    public void u(Object obj, String str) throws IOException {
        boolean zCommit;
        boolean z = obj instanceof String;
        String str2 = (String) this.a;
        SharedPreferences sharedPreferences = (SharedPreferences) this.b;
        if (z) {
            zCommit = sharedPreferences.edit().putString(str, (String) obj).commit();
        } else if (obj instanceof Long) {
            zCommit = sharedPreferences.edit().putLong(str, ((Long) obj).longValue()).commit();
        } else if (obj instanceof Boolean) {
            zCommit = sharedPreferences.edit().putBoolean(str, ((Boolean) obj).booleanValue()).commit();
        } else {
            if (!(obj instanceof Integer)) {
                Log.e("GpidLifecycleSPHandler", "Unexpected object class " + String.valueOf(obj.getClass()) + " for app " + str2);
                throw new IOException(android.support.v4.media.session.a.m("Failed to store ", str, " for app ", str2));
            }
            zCommit = sharedPreferences.edit().putInt(str, ((Integer) obj).intValue()).commit();
        }
        if (zCommit) {
            return;
        }
        throw new IOException(android.support.v4.media.session.a.m("Failed to store ", str, " for app ", str2));
    }

    public void v(String str) throws IOException {
        if (((SharedPreferences) this.b).edit().remove(str).commit()) {
            return;
        }
        StringBuilder sbY = android.support.v4.media.session.a.y("Failed to remove ", str, " for app ");
        sbY.append((String) this.a);
        throw new IOException(sbY.toString());
    }

    @Override // com.google.android.gms.internal.ads.GE
    public int zza() {
        return ((MediaCodec) this.a).dequeueInputBuffer(0L);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void zzi() {
        ((MediaCodec) this.a).detachOutputSurface();
    }

    public Ps(int i, int i2) {
        this.a = i == 0 ? Collections.EMPTY_LIST : new ArrayList(i);
        this.b = i2 == 0 ? Collections.EMPTY_LIST : new ArrayList(i2);
    }

    public Ps(Context context) {
        this.a = context.getPackageName();
        this.b = context.getSharedPreferences("paid_storage_sp", 0);
    }

    public Ps(MediaCodec mediaCodec, Fp fp) {
        this.a = mediaCodec;
        this.b = fp;
        if (Build.VERSION.SDK_INT < 35 || fp == null) {
            return;
        }
        LoudnessCodecController loudnessCodecController = (LoudnessCodecController) fp.c;
        if (loudnessCodecController == null || loudnessCodecController.addMediaCodec(mediaCodec)) {
            AbstractC1795We.L(((HashSet) fp.b).add(mediaCodec));
        }
    }

    public /* synthetic */ Ps() {
        this.a = new HashMap();
        this.b = new HashMap();
    }

    public /* synthetic */ Ps(C2291ky c2291ky) {
        this.a = new HashMap(c2291ky.a);
        this.b = new HashMap(c2291ky.b);
    }
}
