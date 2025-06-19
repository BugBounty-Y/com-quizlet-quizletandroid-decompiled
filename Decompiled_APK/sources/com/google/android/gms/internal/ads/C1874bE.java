package com.google.android.gms.internal.ads;

import android.content.Context;
import android.media.metrics.PlaybackMetrics;
import android.media.metrics.PlaybackSession;
import android.media.metrics.TrackChangeEvent;
import android.os.SystemClock;
import android.util.Pair;
import java.io.IOException;
import java.util.HashMap;
import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.internal.ads.bE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1874bE implements SD {
    public final Context a;
    public final YD c;
    public final PlaybackSession d;
    public String j;
    public PlaybackMetrics.Builder k;
    public zzba n;
    public Ps o;
    public Ps p;
    public Ps q;
    public C1832aG r;
    public C1832aG s;
    public C1832aG t;
    public boolean u;
    public boolean v;
    public int w;
    public int x;
    public int y;
    public boolean z;
    public final Executor b = AbstractC1972di.d();
    public final C2518q9 f = new C2518q9();
    public final C2303l9 g = new C2303l9();
    public final HashMap i = new HashMap();
    public final HashMap h = new HashMap();
    public final long e = SystemClock.elapsedRealtime();
    public int l = 0;
    public int m = 0;

    public C1874bE(Context context, PlaybackSession playbackSession) {
        this.a = context.getApplicationContext();
        this.d = playbackSession;
        YD yd = new YD();
        this.c = yd;
        yd.d = this;
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void a(IOException iOException) {
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:20:0x004e  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00a5  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00d1  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(com.google.android.gms.internal.ads.A9 r10, com.google.android.gms.internal.ads.C2093gF r11) {
        /*
            Method dump skipped, instructions count: 290
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1874bE.b(com.google.android.gms.internal.ads.A9, com.google.android.gms.internal.ads.gF):void");
    }

    public final void c(int i, long j, C1832aG c1832aG, int i2) {
        TrackChangeEvent.Builder timeSinceCreatedMillis = AbstractC1830aE.o(i).setTimeSinceCreatedMillis(j - this.e);
        if (c1832aG != null) {
            timeSinceCreatedMillis.setTrackState(1);
            timeSinceCreatedMillis.setTrackChangeReason(i2 != 1 ? 1 : 2);
            String str = c1832aG.l;
            if (str != null) {
                timeSinceCreatedMillis.setContainerMimeType(str);
            }
            String str2 = c1832aG.m;
            if (str2 != null) {
                timeSinceCreatedMillis.setSampleMimeType(str2);
            }
            String str3 = c1832aG.j;
            if (str3 != null) {
                timeSinceCreatedMillis.setCodecName(str3);
            }
            int i3 = c1832aG.i;
            if (i3 != -1) {
                timeSinceCreatedMillis.setBitrate(i3);
            }
            int i4 = c1832aG.t;
            if (i4 != -1) {
                timeSinceCreatedMillis.setWidth(i4);
            }
            int i5 = c1832aG.u;
            if (i5 != -1) {
                timeSinceCreatedMillis.setHeight(i5);
            }
            int i6 = c1832aG.C;
            if (i6 != -1) {
                timeSinceCreatedMillis.setChannelCount(i6);
            }
            int i7 = c1832aG.D;
            if (i7 != -1) {
                timeSinceCreatedMillis.setAudioSampleRate(i7);
            }
            String str4 = c1832aG.d;
            if (str4 != null) {
                String str5 = Yo.a;
                String[] strArrSplit = str4.split("-", -1);
                Pair pairCreate = Pair.create(strArrSplit[0], strArrSplit.length >= 2 ? strArrSplit[1] : null);
                timeSinceCreatedMillis.setLanguage((String) pairCreate.first);
                Object obj = pairCreate.second;
                if (obj != null) {
                    timeSinceCreatedMillis.setLanguageRegion((String) obj);
                }
            }
            float f = c1832aG.v;
            if (f != -1.0f) {
                timeSinceCreatedMillis.setVideoFrameRate(f);
            }
        } else {
            timeSinceCreatedMillis.setTrackState(0);
        }
        this.z = true;
        this.b.execute(new RunnableC2793wl(18, this, timeSinceCreatedMillis.build()));
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void d(C1740Nd c1740Nd) {
        Ps ps = this.o;
        if (ps != null) {
            C1832aG c1832aG = (C1832aG) ps.b;
            if (c1832aG.u == -1) {
                EF ef = new EF(c1832aG);
                ef.s = c1740Nd.a;
                ef.t = c1740Nd.b;
                this.o = new Ps(new C1832aG(ef), (String) ps.a);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final /* synthetic */ void e() {
    }

    public final boolean f(Ps ps) {
        String str;
        if (ps == null) {
            return false;
        }
        YD yd = this.c;
        String str2 = (String) ps.a;
        synchronized (yd) {
            str = yd.f;
        }
        return str2.equals(str);
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final /* synthetic */ void g(int i) {
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void h(RD rd, int i, long j) {
        C2093gF c2093gF = rd.d;
        if (c2093gF != null) {
            String strA = this.c.a(rd.b, c2093gF);
            HashMap map = this.i;
            Long l = (Long) map.get(strA);
            HashMap map2 = this.h;
            Long l2 = (Long) map2.get(strA);
            map.put(strA, Long.valueOf((l == null ? 0L : l.longValue()) + j));
            map2.put(strA, Long.valueOf((l2 != null ? l2.longValue() : 0L) + i));
        }
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final /* synthetic */ void i(C1832aG c1832aG) {
    }

    /* JADX WARN: Removed duplicated region for block: B:139:0x0215 A[PHI: r5
  0x0215: PHI (r5v40 int) = (r5v28 int), (r5v64 int) binds: [B:214:0x0309, B:138:0x0212] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:140:0x0218 A[PHI: r5
  0x0218: PHI (r5v39 int) = (r5v28 int), (r5v64 int) binds: [B:214:0x0309, B:138:0x0212] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:141:0x021b A[PHI: r5
  0x021b: PHI (r5v38 int) = (r5v28 int), (r5v64 int) binds: [B:214:0x0309, B:138:0x0212] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:142:0x021e A[PHI: r5
  0x021e: PHI (r5v37 int) = (r5v28 int), (r5v64 int) binds: [B:214:0x0309, B:138:0x0212] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:155:0x023c  */
    /* JADX WARN: Type inference failed for: r8v0 */
    /* JADX WARN: Type inference failed for: r8v1, types: [com.google.android.gms.internal.ads.Ps, java.lang.Throwable] */
    /* JADX WARN: Type inference failed for: r8v3 */
    @Override // com.google.android.gms.internal.ads.SD
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void j(com.google.android.gms.internal.ads.PD r25, com.google.android.gms.internal.ads.Fp r26) throws java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 1436
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1874bE.j(com.google.android.gms.internal.ads.PD, com.google.android.gms.internal.ads.Fp):void");
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void k(QC qc) {
        this.w += qc.g;
        this.x += qc.e;
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final /* synthetic */ void k0(int i) {
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final /* synthetic */ void l(C1832aG c1832aG) {
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void m(zzba zzbaVar) {
        this.n = zzbaVar;
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void n(int i) {
        if (i == 1) {
            this.u = true;
        }
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void o(RD rd, androidx.compose.animation.core.S0 s0) {
        C2093gF c2093gF = rd.d;
        if (c2093gF == null) {
            return;
        }
        C1832aG c1832aG = (C1832aG) s0.d;
        c1832aG.getClass();
        Ps ps = new Ps(c1832aG, this.c.a(rd.b, c2093gF));
        int i = s0.a;
        if (i != 0) {
            if (i == 1) {
                this.p = ps;
                return;
            } else if (i != 2) {
                if (i != 3) {
                    return;
                }
                this.q = ps;
                return;
            }
        }
        this.o = ps;
    }

    public final void p(RD rd, String str) {
        C2093gF c2093gF = rd.d;
        if ((c2093gF == null || !c2093gF.b()) && str.equals(this.j)) {
            q();
        }
        this.h.remove(str);
        this.i.remove(str);
    }

    public final void q() {
        PlaybackMetrics.Builder builder = this.k;
        if (builder != null && this.z) {
            builder.setAudioUnderrunCount(this.y);
            this.k.setVideoFramesDropped(this.w);
            this.k.setVideoFramesPlayed(this.x);
            Long l = (Long) this.h.get(this.j);
            this.k.setNetworkTransferDurationMillis(l == null ? 0L : l.longValue());
            Long l2 = (Long) this.i.get(this.j);
            this.k.setNetworkBytesRead(l2 == null ? 0L : l2.longValue());
            this.k.setStreamSource((l2 == null || l2.longValue() <= 0) ? 0 : 1);
            this.b.execute(new RunnableC2793wl(21, this, this.k.build()));
        }
        this.k = null;
        this.j = null;
        this.y = 0;
        this.w = 0;
        this.x = 0;
        this.r = null;
        this.s = null;
        this.t = null;
        this.z = false;
    }
}
