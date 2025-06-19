package com.google.android.gms.internal.ads;

import androidx.compose.ui.text.input.C1007j;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.math.RoundingMode;

/* renamed from: com.google.android.gms.internal.ads.k3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2254k3 implements InterfaceC2297l3 {
    public static final int[] m = {-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8};
    public static final int[] n = {7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED, 118, 130, 143, 157, 173, 190, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_MOVED_REGION, 230, 253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767};
    public final C2695uF a;
    public final InterfaceC2380n0 b;
    public final C1007j c;
    public final int d;
    public final byte[] e;
    public final Kn f;
    public final int g;
    public final C1832aG h;
    public int i;
    public long j;
    public int k;
    public long l;

    public C2254k3(C2695uF c2695uF, InterfaceC2380n0 interfaceC2380n0, C1007j c1007j) throws zzaz {
        this.a = c2695uF;
        this.b = interfaceC2380n0;
        this.c = c1007j;
        int i = c1007j.c;
        int iMax = Math.max(1, i / 10);
        this.g = iMax;
        Kn kn = new Kn((byte[]) c1007j.f);
        kn.x();
        int iX = kn.x();
        this.d = iX;
        int i2 = c1007j.b;
        int i3 = c1007j.d;
        int i4 = (((i3 - (i2 * 4)) * 8) / (c1007j.e * i2)) + 1;
        if (iX != i4) {
            throw zzaz.a(null, "Expected frames per block: " + i4 + "; got: " + iX);
        }
        String str = Yo.a;
        int i5 = ((iMax + iX) - 1) / iX;
        this.e = new byte[i5 * i3];
        this.f = new Kn((iX + iX) * i2 * i5);
        int i6 = ((i3 * i) * 8) / iX;
        EF ef = new EF();
        ef.d("audio/raw");
        ef.g = i6;
        ef.h = i6;
        ef.m = (iMax + iMax) * i2;
        ef.B = i2;
        ef.C = i;
        ef.D = 2;
        this.h = new C1832aG(ef);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2297l3
    public final void a(long j) {
        this.i = 0;
        this.j = j;
        this.k = 0;
        this.l = 0L;
    }

    public final void b(int i) {
        C1007j c1007j = this.c;
        long jV = this.j + Yo.v(this.l, 1000000L, c1007j.c, RoundingMode.DOWN);
        int i2 = (i + i) * c1007j.b;
        this.b.f(jV, 1, i2, this.k - i2, null);
        this.l += i;
        this.k -= i2;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2297l3
    public final void e(int i, long j) {
        this.a.p(new C2469p3(this.c, this.d, i, j));
        this.b.a(this.h);
    }

    /*  JADX ERROR: JadxOverflowException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxOverflowException: Regions count limit reached
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0046 A[ADDED_TO_REGION, EDGE_INSN: B:43:0x0046->B:14:0x0046 BREAK  A[LOOP:0: B:6:0x0025->B:13:0x0040], REMOVE, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0029  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:11:0x003d -> B:4:0x0022). Please report as a decompilation issue!!! */
    @Override // com.google.android.gms.internal.ads.InterfaceC2297l3
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean f(com.google.android.gms.internal.ads.P r25, long r26) {
        /*
            Method dump skipped, instructions count: 329
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2254k3.f(com.google.android.gms.internal.ads.P, long):boolean");
    }
}
