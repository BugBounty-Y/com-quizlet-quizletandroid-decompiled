package com.google.android.gms.internal.ads;

import android.media.AudioTimestamp;
import android.media.AudioTrack;
import android.os.Handler;
import android.os.SystemClock;
import java.lang.reflect.Method;
import java.math.RoundingMode;

/* renamed from: com.google.android.gms.internal.ads.kE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2265kE {
    public long A;
    public boolean B;
    public long C;
    public long D;
    public C1847ao E;
    public final Lr a;
    public final long[] b;
    public AudioTrack c;
    public int d;
    public C2222jE e;
    public int f;
    public long g;
    public float h;
    public boolean i;
    public long j;
    public long k;
    public Method l;
    public long m;
    public boolean n;
    public boolean o;
    public long p;
    public long q;
    public long r;
    public long s;
    public int t;
    public int u;
    public long v;
    public long w;
    public long x;
    public long y;
    public long z;

    public C2265kE(Lr lr) {
        this.a = lr;
        try {
            this.l = AudioTrack.class.getMethod("getLatency", null);
        } catch (NoSuchMethodException unused) {
        }
        this.b = new long[10];
        this.E = C1847ao.a;
    }

    public final long a() {
        AudioTrack audioTrack;
        C2608sE c2608sE;
        long j;
        boolean z;
        float f;
        C2265kE c2265kE;
        long jMax;
        boolean timestamp;
        long j2;
        AudioTrack audioTrack2;
        long j3;
        Method method;
        AudioTrack audioTrack3;
        AudioTrack audioTrack4 = this.c;
        audioTrack4.getClass();
        int playState = audioTrack4.getPlayState();
        C2608sE c2608sE2 = (C2608sE) this.a.b;
        if (playState == 3) {
            this.E.getClass();
            long jNanoTime = System.nanoTime() / 1000;
            if (jNanoTime - this.k >= 30000) {
                long jU = Yo.u(this.f, c());
                if (jU != 0) {
                    int i = this.t;
                    f = 1.0f;
                    float f2 = this.h;
                    if (f2 != 1.0f) {
                        jU = Math.round(jU / f2);
                    }
                    long[] jArr = this.b;
                    jArr[i] = jU - jNanoTime;
                    this.t = (this.t + 1) % 10;
                    int i2 = this.u;
                    if (i2 < 10) {
                        this.u = i2 + 1;
                    }
                    this.k = jNanoTime;
                    this.j = 0L;
                    int i3 = 0;
                    while (true) {
                        int i4 = this.u;
                        if (i3 >= i4) {
                            break;
                        }
                        this.j = (jArr[i3] / i4) + this.j;
                        i3++;
                    }
                } else {
                    audioTrack = audioTrack4;
                    f = 1.0f;
                    j = 1000;
                    z = false;
                    c2265kE = this;
                    c2608sE = c2608sE2;
                }
            } else {
                f = 1.0f;
            }
            C2222jE c2222jE = this.e;
            c2222jE.getClass();
            long j4 = jNanoTime - c2222jE.e;
            long j5 = c2222jE.d;
            C2554r3 c2554r3 = c2222jE.a;
            if (j4 < j5) {
                audioTrack2 = audioTrack4;
                timestamp = false;
                j2 = 500000;
            } else {
                c2222jE.e = jNanoTime;
                AudioTrack audioTrack5 = (AudioTrack) c2554r3.d;
                AudioTimestamp audioTimestamp = (AudioTimestamp) c2554r3.e;
                timestamp = audioTrack5.getTimestamp(audioTimestamp);
                if (timestamp) {
                    j2 = 500000;
                    long j6 = audioTimestamp.framePosition;
                    if (c2554r3.b > j6) {
                        c2554r3.a++;
                    }
                    c2554r3.b = j6;
                    c2554r3.c = j6 + (c2554r3.a << 32);
                } else {
                    j2 = 500000;
                }
                int i5 = c2222jE.b;
                if (i5 != 0) {
                    if (i5 != 1) {
                        if (i5 != 2) {
                            if (i5 == 3) {
                                if (timestamp) {
                                    c2222jE.a(0);
                                } else {
                                    audioTrack2 = audioTrack4;
                                }
                            }
                            audioTrack2 = audioTrack4;
                        } else if (!timestamp) {
                            c2222jE.a(0);
                            audioTrack2 = audioTrack4;
                            timestamp = false;
                        }
                        timestamp = true;
                        audioTrack2 = audioTrack4;
                    } else if (timestamp) {
                        audioTrack2 = audioTrack4;
                        if (c2554r3.c > c2222jE.f) {
                            c2222jE.a(2);
                        }
                        timestamp = true;
                    } else {
                        audioTrack2 = audioTrack4;
                        c2222jE.a(0);
                    }
                    timestamp = false;
                } else {
                    audioTrack2 = audioTrack4;
                    if (timestamp) {
                        if (audioTimestamp.nanoTime / 1000 >= c2222jE.c) {
                            c2222jE.f = c2554r3.c;
                            c2222jE.a(1);
                            timestamp = true;
                        }
                    } else if (jNanoTime - c2222jE.c > j2) {
                        c2222jE.a(3);
                    }
                    timestamp = false;
                }
            }
            String str = "DefaultAudioSink";
            if (timestamp) {
                long j7 = ((AudioTimestamp) c2554r3.e).nanoTime / 1000;
                j3 = 5000000;
                long j8 = c2554r3.c;
                long jU2 = Yo.u(this.f, c());
                j = 1000;
                if (Math.abs(j7 - jNanoTime) > 5000000) {
                    long jA = c2608sE2.a();
                    long jB = c2608sE2.b();
                    StringBuilder sbT = androidx.compose.animation.d0.t(j8, "Spurious audio timestamp (system clock mismatch): ", ", ");
                    sbT.append(j7);
                    sbT.append(", ");
                    sbT.append(jNanoTime);
                    sbT.append(", ");
                    sbT.append(jU2);
                    sbT.append(", ");
                    sbT.append(jA);
                    sbT.append(", ");
                    sbT.append(jB);
                    str = "DefaultAudioSink";
                    AbstractC2096gb.J(str, sbT.toString());
                    c2222jE.a(4);
                    c2265kE = this;
                    c2608sE = c2608sE2;
                    audioTrack = audioTrack2;
                } else {
                    c2265kE = this;
                    if (Math.abs(Yo.u(c2265kE.f, j8) - jU2) > 5000000) {
                        c2608sE = c2608sE2;
                        long jA2 = c2608sE.a();
                        long jB2 = c2608sE.b();
                        audioTrack = audioTrack2;
                        StringBuilder sbT2 = androidx.compose.animation.d0.t(j8, "Spurious audio timestamp (frame position mismatch): ", ", ");
                        sbT2.append(j7);
                        sbT2.append(", ");
                        sbT2.append(jNanoTime);
                        sbT2.append(", ");
                        sbT2.append(jU2);
                        sbT2.append(", ");
                        sbT2.append(jA2);
                        sbT2.append(", ");
                        sbT2.append(jB2);
                        str = "DefaultAudioSink";
                        AbstractC2096gb.J(str, sbT2.toString());
                        c2222jE.a(4);
                    } else {
                        c2608sE = c2608sE2;
                        audioTrack = audioTrack2;
                        if (c2222jE.b == 4) {
                            z = false;
                            c2222jE.a(0);
                        }
                    }
                }
                z = false;
            } else {
                c2265kE = this;
                audioTrack = audioTrack2;
                j = 1000;
                z = false;
                j3 = 5000000;
                c2608sE = c2608sE2;
            }
            if (c2265kE.o && (method = c2265kE.l) != null && jNanoTime - c2265kE.p >= j2) {
                try {
                    audioTrack3 = c2265kE.c;
                } catch (Exception unused) {
                    c2265kE.l = null;
                }
                if (audioTrack3 == null) {
                    throw null;
                }
                Integer num = (Integer) method.invoke(audioTrack3, null);
                String str2 = Yo.a;
                long jIntValue = (num.intValue() * j) - c2265kE.g;
                c2265kE.m = jIntValue;
                long jMax2 = Math.max(jIntValue, 0L);
                c2265kE.m = jMax2;
                if (jMax2 > j3) {
                    AbstractC2096gb.J(str, "Ignoring impossibly large audio latency: " + jMax2);
                    c2265kE.m = 0L;
                }
                c2265kE.p = jNanoTime;
            }
        } else {
            audioTrack = audioTrack4;
            c2608sE = c2608sE2;
            j = 1000;
            z = false;
            f = 1.0f;
            c2265kE = this;
        }
        c2265kE.E.getClass();
        long jNanoTime2 = System.nanoTime() / j;
        C2222jE c2222jE2 = c2265kE.e;
        c2222jE2.getClass();
        boolean z2 = c2222jE2.b == 2 ? true : z;
        if (z2) {
            C2554r3 c2554r32 = c2222jE2.a;
            jMax = Yo.s(jNanoTime2 - (((AudioTimestamp) c2554r32.e).nanoTime / j), c2265kE.h) + Yo.u(c2265kE.f, c2554r32.c);
        } else {
            jMax = Math.max(0L, (c2265kE.u == 0 ? c2265kE.v != -9223372036854775807L ? Yo.u(c2265kE.f, c2265kE.d()) : Yo.u(c2265kE.f, c2265kE.c()) : Yo.s(c2265kE.j + jNanoTime2, c2265kE.h)) - c2265kE.m);
            if (c2265kE.v != -9223372036854775807L) {
                jMax = Math.min(Yo.u(c2265kE.f, c2265kE.y), jMax);
            }
        }
        if (c2265kE.B != z2) {
            c2265kE.D = c2265kE.A;
            c2265kE.C = c2265kE.z;
        }
        long j9 = jNanoTime2 - c2265kE.D;
        if (j9 < 1000000) {
            long jS = Yo.s(j9, c2265kE.h) + c2265kE.C;
            long j10 = (j9 * j) / 1000000;
            jMax = (((j - j10) * jS) + (jMax * j10)) / j;
        }
        if (!c2265kE.i && jMax > c2265kE.z && audioTrack.getPlayState() == 3) {
            c2265kE.i = true;
            long j11 = jMax - c2265kE.z;
            float f3 = c2265kE.h;
            long jW = Yo.w(j11);
            if (f3 != f) {
                jW = Math.round(jW / f3);
            }
            c2265kE.E.getClass();
            long jCurrentTimeMillis = System.currentTimeMillis() - Yo.w(jW);
            Sq sq = c2608sE.l;
            if (sq != null) {
                Fp fp = ((C2651tE) sq.a).F1;
                Handler handler = (Handler) fp.b;
                if (handler != null) {
                    handler.post(new RunnableC2180iE(fp, jCurrentTimeMillis));
                }
            }
        }
        c2265kE.A = jNanoTime2;
        c2265kE.z = jMax;
        c2265kE.B = z2;
        return jMax;
    }

    public final void b(AudioTrack audioTrack, int i, int i2, int i3) {
        long jU;
        this.c = audioTrack;
        this.d = i3;
        this.e = new C2222jE(audioTrack);
        this.f = audioTrack.getSampleRate();
        boolean zC = Yo.c(i);
        this.o = zC;
        if (zC) {
            jU = Yo.u(this.f, i3 / i2);
        } else {
            jU = -9223372036854775807L;
        }
        this.g = jU;
        this.r = 0L;
        this.s = 0L;
        this.n = false;
        this.v = -9223372036854775807L;
        this.w = -9223372036854775807L;
        this.p = 0L;
        this.m = 0L;
        this.h = 1.0f;
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0068  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long c() {
        /*
            r10 = this;
            long r0 = r10.v
            r2 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            int r0 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r0 == 0) goto L16
            long r0 = r10.d()
            long r2 = r10.y
            long r0 = java.lang.Math.min(r2, r0)
            return r0
        L16:
            com.google.android.gms.internal.ads.ao r0 = r10.E
            r0.getClass()
            long r0 = android.os.SystemClock.elapsedRealtime()
            long r4 = r10.q
            long r4 = r0 - r4
            r6 = 5
            int r4 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r4 < 0) goto L73
            android.media.AudioTrack r4 = r10.c
            r4.getClass()
            int r5 = r4.getPlayState()
            r6 = 1
            if (r5 != r6) goto L36
            goto L71
        L36:
            int r4 = r4.getPlaybackHeadPosition()
            long r6 = (long) r4
            int r4 = android.os.Build.VERSION.SDK_INT
            r8 = 4294967295(0xffffffff, double:2.1219957905E-314)
            long r6 = r6 & r8
            r8 = 29
            if (r4 > r8) goto L62
            r8 = 0
            int r4 = (r6 > r8 ? 1 : (r6 == r8 ? 0 : -1))
            if (r4 != 0) goto L60
            long r6 = r10.r
            int r4 = (r6 > r8 ? 1 : (r6 == r8 ? 0 : -1))
            if (r4 <= 0) goto L5f
            r4 = 3
            if (r5 != r4) goto L5f
            long r4 = r10.w
            int r2 = (r4 > r2 ? 1 : (r4 == r2 ? 0 : -1))
            if (r2 != 0) goto L71
            r10.w = r0
            goto L71
        L5f:
            r6 = r8
        L60:
            r10.w = r2
        L62:
            long r2 = r10.r
            int r2 = (r2 > r6 ? 1 : (r2 == r6 ? 0 : -1))
            if (r2 <= 0) goto L6f
            long r2 = r10.s
            r4 = 1
            long r2 = r2 + r4
            r10.s = r2
        L6f:
            r10.r = r6
        L71:
            r10.q = r0
        L73:
            long r0 = r10.r
            long r2 = r10.s
            r4 = 32
            long r2 = r2 << r4
            long r0 = r0 + r2
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2265kE.c():long");
    }

    public final long d() {
        AudioTrack audioTrack = this.c;
        audioTrack.getClass();
        if (audioTrack.getPlayState() == 2) {
            return this.x;
        }
        this.E.getClass();
        return this.x + Yo.v(Yo.s(Yo.t(SystemClock.elapsedRealtime()) - this.v, this.h), this.f, 1000000L, RoundingMode.UP);
    }
}
