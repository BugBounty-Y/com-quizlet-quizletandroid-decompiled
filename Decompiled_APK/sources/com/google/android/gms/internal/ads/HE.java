package com.google.android.gms.internal.ads;

import android.graphics.Point;
import android.media.MediaCodecInfo;
import android.os.Build;
import android.util.Pair;
import android.util.Range;
import java.util.HashMap;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class HE {
    public final String a;
    public final String b;
    public final String c;
    public final MediaCodecInfo.CodecCapabilities d;
    public final boolean e;
    public final boolean f;
    public final boolean g;
    public final boolean h;
    public final boolean i;

    public HE(String str, String str2, String str3, MediaCodecInfo.CodecCapabilities codecCapabilities, boolean z, boolean z2, boolean z3, boolean z4) {
        str.getClass();
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = codecCapabilities;
        this.g = z;
        this.e = z2;
        this.f = z3;
        this.h = z4;
        this.i = AbstractC2514q5.j(str2);
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x0049  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.ads.HE b(java.lang.String r9, java.lang.String r10, java.lang.String r11, android.media.MediaCodecInfo.CodecCapabilities r12, boolean r13, boolean r14) {
        /*
            com.google.android.gms.internal.ads.HE r0 = new com.google.android.gms.internal.ads.HE
            r1 = 1
            r2 = 0
            if (r12 == 0) goto L10
            java.lang.String r3 = "adaptive-playback"
            boolean r3 = r12.isFeatureSupported(r3)
            if (r3 == 0) goto L10
            r6 = r1
            goto L11
        L10:
            r6 = r2
        L11:
            if (r12 == 0) goto L18
            java.lang.String r3 = "tunneled-playback"
            r12.isFeatureSupported(r3)
        L18:
            if (r14 != 0) goto L24
            if (r12 == 0) goto L26
            java.lang.String r14 = "secure-playback"
            boolean r14 = r12.isFeatureSupported(r14)
            if (r14 == 0) goto L26
        L24:
            r7 = r1
            goto L27
        L26:
            r7 = r2
        L27:
            int r14 = android.os.Build.VERSION.SDK_INT
            r3 = 35
            if (r14 < r3) goto L49
            if (r12 == 0) goto L49
            java.lang.String r14 = "detached-surface"
            boolean r14 = r12.isFeatureSupported(r14)
            if (r14 == 0) goto L49
            java.lang.String r14 = android.os.Build.MANUFACTURER
            java.lang.String r3 = "Xiaomi"
            boolean r3 = r14.equals(r3)
            if (r3 != 0) goto L49
            java.lang.String r3 = "OPPO"
            boolean r14 = r14.equals(r3)
            if (r14 == 0) goto L50
        L49:
            r1 = r9
            r3 = r11
            r4 = r12
            r5 = r13
            r8 = r2
            r2 = r10
            goto L56
        L50:
            r2 = r10
            r3 = r11
            r4 = r12
            r5 = r13
            r8 = r1
            r1 = r9
        L56:
            r0.<init>(r1, r2, r3, r4, r5, r6, r7, r8)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.HE.b(java.lang.String, java.lang.String, java.lang.String, android.media.MediaCodecInfo$CodecCapabilities, boolean, boolean):com.google.android.gms.internal.ads.HE");
    }

    public static Point f(MediaCodecInfo.VideoCapabilities videoCapabilities, int i, int i2) {
        int widthAlignment = videoCapabilities.getWidthAlignment();
        int heightAlignment = videoCapabilities.getHeightAlignment();
        String str = Yo.a;
        return new Point((((i + widthAlignment) - 1) / widthAlignment) * widthAlignment, (((i2 + heightAlignment) - 1) / heightAlignment) * heightAlignment);
    }

    public static boolean h(MediaCodecInfo.VideoCapabilities videoCapabilities, int i, int i2, double d) {
        Point pointF = f(videoCapabilities, i, i2);
        int i3 = pointF.x;
        int i4 = pointF.y;
        if (d == -1.0d || d < 1.0d) {
            return videoCapabilities.isSizeSupported(i3, i4);
        }
        double dFloor = Math.floor(d);
        if (!videoCapabilities.areSizeAndRateSupported(i3, i4, dFloor)) {
            return false;
        }
        Range<Double> achievableFrameRatesFor = videoCapabilities.getAchievableFrameRatesFor(i3, i4);
        return achievableFrameRatesFor == null || dFloor <= ((Double) achievableFrameRatesFor.getUpper()).doubleValue();
    }

    public final RC a(C1832aG c1832aG, C1832aG c1832aG2) {
        C1832aG c1832aG3;
        C1832aG c1832aG4;
        int i = true != Objects.equals(c1832aG.m, c1832aG2.m) ? 8 : 0;
        if (this.i) {
            if (c1832aG.w != c1832aG2.w) {
                i |= 1024;
            }
            if (!this.e && (c1832aG.t != c1832aG2.t || c1832aG.u != c1832aG2.u)) {
                i |= com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
            }
            C2135hD c2135hD = c1832aG.A;
            boolean zE = C2135hD.e(c2135hD);
            C2135hD c2135hD2 = c1832aG2.A;
            if ((!zE || !C2135hD.e(c2135hD2)) && !Objects.equals(c2135hD, c2135hD2)) {
                i |= 2048;
            }
            boolean zStartsWith = Build.MODEL.startsWith("SM-T230");
            String str = this.a;
            if (zStartsWith && "OMX.MARVELL.VIDEO.HW.CODA7542DECODER".equals(str) && !c1832aG.b(c1832aG2)) {
                i |= 2;
            }
            if (i == 0) {
                return new RC(str, c1832aG, c1832aG2, true == c1832aG.b(c1832aG2) ? 3 : 2, 0);
            }
            c1832aG3 = c1832aG;
            c1832aG4 = c1832aG2;
        } else {
            c1832aG3 = c1832aG;
            c1832aG4 = c1832aG2;
            if (c1832aG3.C != c1832aG4.C) {
                i |= 4096;
            }
            if (c1832aG3.D != c1832aG4.D) {
                i |= 8192;
            }
            if (c1832aG3.E != c1832aG4.E) {
                i |= 16384;
            }
            String str2 = this.b;
            if (i == 0 && "audio/mp4a-latm".equals(str2)) {
                HashMap map = ME.a;
                Pair pairA = Hi.a(c1832aG3);
                Pair pairA2 = Hi.a(c1832aG4);
                if (pairA != null && pairA2 != null) {
                    int iIntValue = ((Integer) pairA.first).intValue();
                    int iIntValue2 = ((Integer) pairA2.first).intValue();
                    if (iIntValue == 42 && iIntValue2 == 42) {
                        return new RC(this.a, c1832aG3, c1832aG4, 3, 0);
                    }
                }
            }
            if (!c1832aG3.b(c1832aG4)) {
                i |= 32;
            }
            if ("audio/opus".equals(str2)) {
                i |= 2;
            }
            if (i == 0) {
                return new RC(this.a, c1832aG3, c1832aG4, 1, 0);
            }
        }
        return new RC(this.a, c1832aG3, c1832aG4, 0, i);
    }

    public final boolean c(C1832aG c1832aG) {
        int i;
        String str = c1832aG.m;
        String str2 = this.b;
        if (!(str2.equals(str) || str2.equals(ME.a(c1832aG))) || !i(c1832aG, true) || !j(c1832aG)) {
            return false;
        }
        if (this.i) {
            int i2 = c1832aG.t;
            if (i2 > 0 && (i = c1832aG.u) > 0) {
                return e(c1832aG.v, i2, i);
            }
        } else {
            MediaCodecInfo.CodecCapabilities codecCapabilities = this.d;
            int i3 = c1832aG.D;
            if (i3 != -1) {
                if (codecCapabilities == null) {
                    g("sampleRate.caps");
                    return false;
                }
                MediaCodecInfo.AudioCapabilities audioCapabilities = codecCapabilities.getAudioCapabilities();
                if (audioCapabilities == null) {
                    g("sampleRate.aCaps");
                    return false;
                }
                if (!audioCapabilities.isSampleRateSupported(i3)) {
                    g("sampleRate.support, " + i3);
                    return false;
                }
            }
            int i4 = c1832aG.C;
            if (i4 != -1) {
                if (codecCapabilities == null) {
                    g("channelCount.caps");
                    return false;
                }
                MediaCodecInfo.AudioCapabilities audioCapabilities2 = codecCapabilities.getAudioCapabilities();
                if (audioCapabilities2 == null) {
                    g("channelCount.aCaps");
                    return false;
                }
                int maxInputChannelCount = audioCapabilities2.getMaxInputChannelCount();
                if (maxInputChannelCount <= 1 && maxInputChannelCount <= 0 && !"audio/mpeg".equals(str2) && !"audio/3gpp".equals(str2) && !"audio/amr-wb".equals(str2) && !"audio/mp4a-latm".equals(str2) && !"audio/vorbis".equals(str2) && !"audio/opus".equals(str2) && !"audio/raw".equals(str2) && !"audio/flac".equals(str2) && !"audio/g711-alaw".equals(str2) && !"audio/g711-mlaw".equals(str2) && !"audio/gsm".equals(str2)) {
                    int i5 = "audio/ac3".equals(str2) ? 6 : "audio/eac3".equals(str2) ? 16 : 30;
                    AbstractC2096gb.J("MediaCodecInfo", "AssumedMaxChannelAdjustment: " + this.a + ", [" + maxInputChannelCount + " to " + i5 + "]");
                    maxInputChannelCount = i5;
                }
                if (maxInputChannelCount < i4) {
                    g("channelCount.support, " + i4);
                    return false;
                }
            }
        }
        return true;
    }

    public final boolean d(C1832aG c1832aG) {
        if (this.i) {
            return this.e;
        }
        HashMap map = ME.a;
        Pair pairA = Hi.a(c1832aG);
        return pairA != null && ((Integer) pairA.first).intValue() == 42;
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x0067  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0087  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x008c  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00a6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean e(double r12, int r14, int r15) {
        /*
            Method dump skipped, instructions count: 262
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.HE.e(double, int, int):boolean");
    }

    public final void g(String str) {
        String str2 = Yo.a;
        StringBuilder sbY = android.support.v4.media.session.a.y("NoSupport [", str, "] [");
        sbY.append(this.a);
        sbY.append(", ");
        sbY.append(this.b);
        sbY.append("] [");
        sbY.append(str2);
        sbY.append("]");
        AbstractC2096gb.p(sbY.toString());
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0048  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00b7  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean i(com.google.android.gms.internal.ads.C1832aG r14, boolean r15) {
        /*
            Method dump skipped, instructions count: 252
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.HE.i(com.google.android.gms.internal.ads.aG, boolean):boolean");
    }

    public final boolean j(C1832aG c1832aG) {
        return (Objects.equals(c1832aG.m, "audio/flac") && c1832aG.E == 22 && Build.VERSION.SDK_INT < 34 && this.a.equals("c2.android.flac.decoder")) ? false : true;
    }

    public final String toString() {
        return this.a;
    }
}
