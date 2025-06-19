package com.google.android.gms.internal.ads;

import androidx.compose.foundation.lazy.layout.C0429a;
import java.util.List;

/* loaded from: classes2.dex */
public final class B0 implements U {
    public final /* synthetic */ int a;
    public final U b;

    public B0(int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = new C2208j0(35152, 2, "image/png");
                break;
            case 2:
                this.b = new J0();
                break;
            default:
                this.b = new C2208j0(16973, 2, "image/bmp");
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) {
        switch (this.a) {
            case 0:
                return ((C2208j0) this.b).d(v);
            case 1:
                return ((C2208j0) this.b).d(v);
            default:
                return ((J0) this.b).d(v);
        }
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        switch (this.a) {
            case 0:
                ((C2208j0) this.b).e(w);
                break;
            case 1:
                ((C2208j0) this.b).e(w);
                break;
            default:
                ((J0) this.b).b = (C2695uF) w;
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.U
    public final int f(V v, C0429a c0429a) {
        switch (this.a) {
            case 0:
                return ((C2208j0) this.b).f(v, c0429a);
            case 1:
                return ((C2208j0) this.b).f(v, c0429a);
            default:
                return ((J0) this.b).f(v, c0429a);
        }
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void h(long j, long j2) {
        switch (this.a) {
            case 0:
                ((C2208j0) this.b).h(j, j2);
                break;
            case 1:
                ((C2208j0) this.b).h(j, j2);
                break;
            default:
                ((J0) this.b).h(j, j2);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.U
    public final List j() {
        switch (this.a) {
            case 0:
                C2244ju c2244ju = AbstractC2330lu.b;
                break;
            case 1:
                C2244ju c2244ju2 = AbstractC2330lu.b;
                break;
            default:
                C2244ju c2244ju3 = AbstractC2330lu.b;
                break;
        }
        return Bu.e;
    }
}
