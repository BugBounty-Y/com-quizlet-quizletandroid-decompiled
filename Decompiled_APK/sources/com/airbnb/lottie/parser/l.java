package com.airbnb.lottie.parser;

import android.content.Context;
import com.google.android.gms.internal.ads.C1868b8;
import com.google.android.gms.internal.ads.Pk;
import com.google.android.gms.internal.ads.RD;
import com.google.android.gms.internal.ads.SD;
import com.google.android.gms.internal.ads.Xh;

/* loaded from: classes.dex */
public final class l implements E, com.google.android.gms.dynamite.a, Xh, Pk {
    public final /* synthetic */ int a;
    public int b;

    /* JADX WARN: Removed duplicated region for block: B:38:0x00d3  */
    @Override // com.airbnb.lottie.parser.E
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(com.airbnb.lottie.parser.moshi.d r21, float r22) {
        /*
            Method dump skipped, instructions count: 632
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.parser.l.a(com.airbnb.lottie.parser.moshi.d, float):java.lang.Object");
    }

    @Override // com.google.android.gms.internal.ads.Xh
    /* renamed from: b */
    public void mo16b(Object obj) {
        switch (this.a) {
            case 4:
                ((com.google.android.gms.ads.internal.overlay.j) obj).X(this.b);
                break;
            case 8:
                ((SD) obj).k0(this.b);
                break;
            case 9:
                ((SD) obj).g(this.b);
                break;
            default:
                ((SD) obj).n(this.b);
                break;
        }
    }

    public String c(String str, String str2, String str3, String str4) {
        return !com.onetrust.otpublishers.headless.Internal.a.j(str) ? str : !com.onetrust.otpublishers.headless.Internal.a.j(str2) ? str2 : this.b == 11 ? str4 : str3;
    }

    @Override // com.google.android.gms.dynamite.a
    public int d(Context context, String str, boolean z) {
        return 0;
    }

    @Override // com.google.android.gms.dynamite.a
    public int e(Context context, String str) {
        return this.b;
    }

    public /* synthetic */ l(int i, int i2) {
        this.a = i2;
        this.b = i;
    }

    public /* synthetic */ l(l lVar) {
        this.a = 6;
        this.b = lVar.b;
    }

    public /* synthetic */ l(RD rd, int i) {
        this.a = 9;
        this.b = i;
    }

    public /* synthetic */ l(RD rd, int i, long j) {
        this.a = 8;
        this.b = i;
    }

    public /* synthetic */ l(RD rd, int i, C1868b8 c1868b8, C1868b8 c1868b82) {
        this.a = 10;
        this.b = i;
    }
}
