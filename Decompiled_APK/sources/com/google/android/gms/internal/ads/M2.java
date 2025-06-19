package com.google.android.gms.internal.ads;

import androidx.compose.material3.C0591b1;
import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public final class M2 implements N2 {
    public final /* synthetic */ int a;
    public boolean b;
    public long c;
    public int d;
    public int e;
    public final Object f;
    public Object g;

    public M2() {
        this.a = 1;
        this.f = new Kn(10);
        this.c = -9223372036854775807L;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void a(boolean z) {
        int i;
        switch (this.a) {
            case 0:
                if (this.b) {
                    AbstractC1795We.L(this.c != -9223372036854775807L);
                    int i2 = 0;
                    while (true) {
                        InterfaceC2380n0[] interfaceC2380n0Arr = (InterfaceC2380n0[]) this.g;
                        if (i2 >= interfaceC2380n0Arr.length) {
                            this.b = false;
                            break;
                        } else {
                            interfaceC2380n0Arr[i2].f(this.c, 1, this.e, 0, null);
                            i2++;
                        }
                    }
                }
                break;
            default:
                AbstractC1795We.p((InterfaceC2380n0) this.g);
                if (this.b && (i = this.d) != 0 && this.e == i) {
                    AbstractC1795We.L(this.c != -9223372036854775807L);
                    ((InterfaceC2380n0) this.g).f(this.c, 1, this.d, 0, null);
                    this.b = false;
                    break;
                }
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void d(Kn kn) {
        boolean z;
        boolean z2;
        switch (this.a) {
            case 0:
                if (this.b) {
                    int i = 0;
                    if (this.d == 2) {
                        if (kn.s() == 0) {
                            z2 = false;
                        } else {
                            if (kn.z() != 32) {
                                this.b = false;
                            }
                            this.d--;
                            z2 = this.b;
                        }
                        if (!z2) {
                        }
                    }
                    if (this.d == 1) {
                        if (kn.s() == 0) {
                            z = false;
                        } else {
                            if (kn.z() != 0) {
                                this.b = false;
                            }
                            this.d--;
                            z = this.b;
                        }
                        if (!z) {
                        }
                    }
                    int i2 = kn.b;
                    int iS = kn.s();
                    while (true) {
                        InterfaceC2380n0[] interfaceC2380n0Arr = (InterfaceC2380n0[]) this.g;
                        if (i >= interfaceC2380n0Arr.length) {
                            this.e += iS;
                            break;
                        } else {
                            InterfaceC2380n0 interfaceC2380n0 = interfaceC2380n0Arr[i];
                            kn.j(i2);
                            interfaceC2380n0.e(iS, kn);
                            i++;
                        }
                    }
                }
                break;
            default:
                AbstractC1795We.p((InterfaceC2380n0) this.g);
                if (this.b) {
                    int iS2 = kn.s();
                    int i3 = this.e;
                    if (i3 < 10) {
                        int iMin = Math.min(iS2, 10 - i3);
                        byte[] bArr = kn.a;
                        int i4 = kn.b;
                        Kn kn2 = (Kn) this.f;
                        System.arraycopy(bArr, i4, kn2.a, this.e, iMin);
                        if (this.e + iMin == 10) {
                            kn2.j(0);
                            if (kn2.z() != 73 || kn2.z() != 68 || kn2.z() != 51) {
                                AbstractC2096gb.J("Id3Reader", "Discarding invalid ID3 tag");
                                this.b = false;
                                break;
                            } else {
                                kn2.k(3);
                                this.d = kn2.y() + 10;
                            }
                        }
                    }
                    int iMin2 = Math.min(iS2, this.d - this.e);
                    ((InterfaceC2380n0) this.g).e(iMin2, kn);
                    this.e += iMin2;
                    break;
                }
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void e(W w, C0591b1 c0591b1) {
        switch (this.a) {
            case 0:
                int i = 0;
                while (true) {
                    InterfaceC2380n0[] interfaceC2380n0Arr = (InterfaceC2380n0[]) this.g;
                    if (i >= interfaceC2380n0Arr.length) {
                        break;
                    } else {
                        C2169i3 c2169i3 = (C2169i3) ((List) this.f).get(i);
                        c0591b1.b();
                        c0591b1.c();
                        InterfaceC2380n0 interfaceC2380n0Q = w.q(c0591b1.c, 3);
                        EF ef = new EF();
                        c0591b1.c();
                        ef.a = (String) c0591b1.e;
                        ef.a("video/mp2t");
                        ef.d("application/dvbsubs");
                        ef.o = Collections.singletonList(c2169i3.b);
                        ef.d = c2169i3.a;
                        interfaceC2380n0Q.a(new C1832aG(ef));
                        interfaceC2380n0Arr[i] = interfaceC2380n0Q;
                        i++;
                    }
                }
            default:
                c0591b1.b();
                c0591b1.c();
                InterfaceC2380n0 interfaceC2380n0Q2 = w.q(c0591b1.c, 5);
                this.g = interfaceC2380n0Q2;
                EF ef2 = new EF();
                c0591b1.c();
                ef2.a = (String) c0591b1.e;
                ef2.a("video/mp2t");
                ef2.d("application/id3");
                interfaceC2380n0Q2.a(new C1832aG(ef2));
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void f(int i, long j) {
        switch (this.a) {
            case 0:
                if ((i & 4) != 0) {
                    this.b = true;
                    this.c = j;
                    this.e = 0;
                    this.d = 2;
                    break;
                }
                break;
            default:
                if ((i & 4) != 0) {
                    this.b = true;
                    this.c = j;
                    this.d = 0;
                    this.e = 0;
                    break;
                }
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void zze() {
        switch (this.a) {
            case 0:
                this.b = false;
                this.c = -9223372036854775807L;
                break;
            default:
                this.b = false;
                this.c = -9223372036854775807L;
                break;
        }
    }

    public M2(List list) {
        this.a = 0;
        this.f = list;
        this.g = new InterfaceC2380n0[list.size()];
        this.c = -9223372036854775807L;
    }
}
