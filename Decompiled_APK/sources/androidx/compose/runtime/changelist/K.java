package androidx.compose.runtime.changelist;

import androidx.core.view.AbstractC1047f0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.ads.C1827aB;
import com.google.android.gms.internal.ads.IA;
import com.google.android.gms.internal.ads.InterfaceC2562rB;
import com.google.android.gms.internal.ads.OA;
import com.google.android.gms.internal.ads.PA;
import com.google.android.gms.internal.ads.VA;
import com.google.android.gms.internal.ads.WA;
import com.google.android.gms.internal.ads.zzgzg;
import com.google.android.gms.internal.ads.zzgzh;
import java.lang.reflect.Array;
import java.nio.charset.Charset;

/* loaded from: classes.dex */
public final class K {
    public final /* synthetic */ int a;
    public int b;
    public int c;
    public int d;
    public Object e;

    public /* synthetic */ K(int i, byte b) {
        this.a = i;
    }

    public static final void A(int i) throws zzgzh {
        if ((i & 7) != 0) {
            throw new zzgzh("Failed to parse the message.");
        }
    }

    public static final void z(int i) throws zzgzh {
        if ((i & 3) != 0) {
            throw new zzgzh("Failed to parse the message.");
        }
    }

    public int B() {
        int iX = this.d;
        if (iX != 0) {
            this.b = iX;
            this.d = 0;
        } else {
            iX = ((AbstractC1047f0) this.e).X();
            this.b = iX;
        }
        return (iX == 0 || iX == this.c) ? SubsamplingScaleImageView.TILE_SIZE_AUTO : iX >>> 3;
    }

    public void C(VA va) throws zzgzh {
        int iX;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        if (i == 0) {
            do {
                va.add(Boolean.valueOf(abstractC1047f0.H()));
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX = abstractC1047f0.X();
                }
            } while (iX == this.b);
            this.d = iX;
            return;
        }
        if (i != 2) {
            throw new zzgzg();
        }
        int iP = abstractC1047f0.P() + abstractC1047f0.Y();
        do {
            va.add(Boolean.valueOf(abstractC1047f0.H()));
        } while (abstractC1047f0.P() < iP);
        x(iP);
    }

    public void D(VA va) throws zzgzg {
        int iX;
        if ((this.b & 7) != 2) {
            throw new zzgzg();
        }
        do {
            y(2);
            AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
            va.add(abstractC1047f0.e0());
            if (abstractC1047f0.G()) {
                return;
            } else {
                iX = abstractC1047f0.X();
            }
        } while (iX == this.b);
        this.d = iX;
    }

    public void E(VA va) throws zzgzh {
        int iX;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        if (i == 1) {
            do {
                va.add(Double.valueOf(abstractC1047f0.L()));
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX = abstractC1047f0.X();
                }
            } while (iX == this.b);
            this.d = iX;
            return;
        }
        if (i != 2) {
            throw new zzgzg();
        }
        int iY = abstractC1047f0.Y();
        A(iY);
        int iP = abstractC1047f0.P() + iY;
        do {
            va.add(Double.valueOf(abstractC1047f0.L()));
        } while (abstractC1047f0.P() < iP);
    }

    public void F(VA va) throws zzgzh {
        int iX;
        int iX2;
        boolean z = va instanceof PA;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        if (z) {
            PA pa = (PA) va;
            int i = this.b & 7;
            if (i != 0) {
                if (i != 2) {
                    throw new zzgzg();
                }
                int iP = abstractC1047f0.P() + abstractC1047f0.Y();
                do {
                    pa.e(abstractC1047f0.S());
                } while (abstractC1047f0.P() < iP);
                x(iP);
                return;
            }
            do {
                pa.e(abstractC1047f0.S());
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX2 = abstractC1047f0.X();
                }
            } while (iX2 == this.b);
        } else {
            int i2 = this.b & 7;
            if (i2 != 0) {
                if (i2 != 2) {
                    throw new zzgzg();
                }
                int iP2 = abstractC1047f0.P() + abstractC1047f0.Y();
                do {
                    va.add(Integer.valueOf(abstractC1047f0.S()));
                } while (abstractC1047f0.P() < iP2);
                x(iP2);
                return;
            }
            do {
                va.add(Integer.valueOf(abstractC1047f0.S()));
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX = abstractC1047f0.X();
                }
            } while (iX == this.b);
            iX2 = iX;
        }
        this.d = iX2;
    }

    public void G(VA va) throws zzgzh {
        int iX;
        int iX2;
        boolean z = va instanceof PA;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        if (z) {
            PA pa = (PA) va;
            int i = this.b & 7;
            if (i == 2) {
                int iY = abstractC1047f0.Y();
                z(iY);
                int iP = abstractC1047f0.P() + iY;
                do {
                    pa.e(abstractC1047f0.T());
                } while (abstractC1047f0.P() < iP);
                return;
            }
            if (i != 5) {
                throw new zzgzg();
            }
            do {
                pa.e(abstractC1047f0.T());
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX2 = abstractC1047f0.X();
                }
            } while (iX2 == this.b);
        } else {
            int i2 = this.b & 7;
            if (i2 == 2) {
                int iY2 = abstractC1047f0.Y();
                z(iY2);
                int iP2 = abstractC1047f0.P() + iY2;
                do {
                    va.add(Integer.valueOf(abstractC1047f0.T()));
                } while (abstractC1047f0.P() < iP2);
                return;
            }
            if (i2 != 5) {
                throw new zzgzg();
            }
            do {
                va.add(Integer.valueOf(abstractC1047f0.T()));
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX = abstractC1047f0.X();
                }
            } while (iX == this.b);
            iX2 = iX;
        }
        this.d = iX2;
    }

    public void a(com.squareup.moshi.z zVar) {
        zVar.c = null;
        zVar.a = null;
        zVar.b = null;
        zVar.i = 1;
        int i = this.b;
        if (i > 0) {
            int i2 = this.d;
            if ((i2 & 1) == 0) {
                this.d = i2 + 1;
                this.b = i - 1;
                this.c++;
            }
        }
        zVar.a = (com.squareup.moshi.z) this.e;
        this.e = zVar;
        int i3 = this.d;
        int i4 = i3 + 1;
        this.d = i4;
        int i5 = this.b;
        if (i5 > 0 && (i4 & 1) == 0) {
            this.d = i3 + 2;
            this.b = i5 - 1;
            this.c++;
        }
        int i6 = 4;
        while (true) {
            int i7 = i6 - 1;
            if ((this.d & i7) != i7) {
                return;
            }
            int i8 = this.c;
            if (i8 == 0) {
                com.squareup.moshi.z zVar2 = (com.squareup.moshi.z) this.e;
                com.squareup.moshi.z zVar3 = zVar2.a;
                com.squareup.moshi.z zVar4 = zVar3.a;
                zVar3.a = zVar4.a;
                this.e = zVar3;
                zVar3.b = zVar4;
                zVar3.c = zVar2;
                zVar3.i = zVar2.i + 1;
                zVar4.a = zVar3;
                zVar2.a = zVar3;
            } else if (i8 == 1) {
                com.squareup.moshi.z zVar5 = (com.squareup.moshi.z) this.e;
                com.squareup.moshi.z zVar6 = zVar5.a;
                this.e = zVar6;
                zVar6.c = zVar5;
                zVar6.i = zVar5.i + 1;
                zVar5.a = zVar6;
                this.c = 0;
            } else if (i8 == 2) {
                this.c = 0;
            }
            i6 *= 2;
        }
    }

    public void b(io.reactivex.rxjava3.disposables.b bVar) {
        Object obj;
        Object obj2;
        Object[] objArr = (Object[]) this.e;
        int i = this.b;
        int iHashCode = bVar.hashCode() * (-1640531527);
        int i2 = (iHashCode ^ (iHashCode >>> 16)) & i;
        Object obj3 = objArr[i2];
        if (obj3 != null) {
            if (obj3.equals(bVar)) {
                return;
            }
            do {
                i2 = (i2 + 1) & i;
                obj2 = objArr[i2];
                if (obj2 == null) {
                }
            } while (!obj2.equals(bVar));
            return;
        }
        objArr[i2] = bVar;
        int i3 = this.c + 1;
        this.c = i3;
        if (i3 < this.d) {
            return;
        }
        Object[] objArr2 = (Object[]) this.e;
        int length = objArr2.length;
        int i4 = length << 1;
        int i5 = i4 - 1;
        Object[] objArr3 = new Object[i4];
        while (true) {
            int i6 = i3 - 1;
            if (i3 == 0) {
                this.b = i5;
                this.d = (int) (i4 * 0.75f);
                this.e = objArr3;
                return;
            }
            do {
                length--;
                obj = objArr2[length];
            } while (obj == null);
            int iHashCode2 = obj.hashCode() * (-1640531527);
            int i7 = (iHashCode2 ^ (iHashCode2 >>> 16)) & i5;
            if (objArr3[i7] != null) {
                do {
                    i7 = (i7 + 1) & i5;
                } while (objArr3[i7] != null);
            }
            objArr3[i7] = objArr2[length];
            i3 = i6;
        }
    }

    public int c() {
        return this.d - this.c;
    }

    public com.google.firebase.crashlytics.internal.metadata.m d() {
        return ((com.google.firebase.crashlytics.internal.metadata.m[]) this.e)[this.b];
    }

    public int e(int i) {
        return ((L) this.e).d[this.c + i];
    }

    public Object f(int i) {
        return ((L) this.e).f[this.d + i];
    }

    public byte[][] g(int i, int i2) {
        int i3 = this.c;
        byte[][] bArr = (byte[][]) Array.newInstance((Class<?>) Byte.TYPE, i3 * i2, this.d * i);
        int i4 = i3 * i2;
        for (int i5 = 0; i5 < i4; i5++) {
            int i6 = (i4 - i5) - 1;
            byte[] bArr2 = ((com.google.firebase.crashlytics.internal.metadata.m[]) this.e)[i5 / i2].a;
            int length = bArr2.length * i;
            byte[] bArr3 = new byte[length];
            for (int i7 = 0; i7 < length; i7++) {
                bArr3[i7] = bArr2[i7 / i];
            }
            bArr[i6] = bArr3;
        }
        return bArr;
    }

    public void h(int i, int i2, Object[] objArr) {
        int i3;
        Object obj;
        this.c--;
        while (true) {
            int i4 = i + 1;
            while (true) {
                i3 = i4 & i2;
                obj = objArr[i3];
                if (obj == null) {
                    objArr[i] = null;
                    return;
                }
                int iHashCode = obj.hashCode() * (-1640531527);
                int i5 = (iHashCode ^ (iHashCode >>> 16)) & i2;
                if (i <= i3) {
                    if (i >= i5 || i5 > i3) {
                        break;
                    } else {
                        i4 = i3 + 1;
                    }
                } else if (i < i5 || i5 <= i3) {
                    i4 = i3 + 1;
                }
            }
            objArr[i] = obj;
            i = i3;
        }
    }

    public void i(VA va) throws zzgzh {
        int iX;
        int iX2;
        boolean z = va instanceof C1827aB;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        if (z) {
            C1827aB c1827aB = (C1827aB) va;
            int i = this.b & 7;
            if (i != 1) {
                if (i != 2) {
                    throw new zzgzg();
                }
                int iY = abstractC1047f0.Y();
                A(iY);
                int iP = abstractC1047f0.P() + iY;
                do {
                    c1827aB.e(abstractC1047f0.Z());
                } while (abstractC1047f0.P() < iP);
                return;
            }
            do {
                c1827aB.e(abstractC1047f0.Z());
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX2 = abstractC1047f0.X();
                }
            } while (iX2 == this.b);
        } else {
            int i2 = this.b & 7;
            if (i2 != 1) {
                if (i2 != 2) {
                    throw new zzgzg();
                }
                int iY2 = abstractC1047f0.Y();
                A(iY2);
                int iP2 = abstractC1047f0.P() + iY2;
                do {
                    va.add(Long.valueOf(abstractC1047f0.Z()));
                } while (abstractC1047f0.P() < iP2);
                return;
            }
            do {
                va.add(Long.valueOf(abstractC1047f0.Z()));
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX = abstractC1047f0.X();
                }
            } while (iX == this.b);
            iX2 = iX;
        }
        this.d = iX2;
    }

    public void j(VA va) throws zzgzh {
        int iX;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        if (i == 2) {
            int iY = abstractC1047f0.Y();
            z(iY);
            int iP = abstractC1047f0.P() + iY;
            do {
                va.add(Float.valueOf(abstractC1047f0.N()));
            } while (abstractC1047f0.P() < iP);
            return;
        }
        if (i != 5) {
            throw new zzgzg();
        }
        do {
            va.add(Float.valueOf(abstractC1047f0.N()));
            if (abstractC1047f0.G()) {
                return;
            } else {
                iX = abstractC1047f0.X();
            }
        } while (iX == this.b);
        this.d = iX;
    }

    public void k(VA va, InterfaceC2562rB interfaceC2562rB, IA ia) throws zzgzg {
        int iX;
        int i = this.b;
        if ((i & 7) != 3) {
            throw new zzgzg();
        }
        do {
            OA oaZze = interfaceC2562rB.zze();
            v(oaZze, interfaceC2562rB, ia);
            interfaceC2562rB.a(oaZze);
            va.add(oaZze);
            AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
            if (abstractC1047f0.G() || this.d != 0) {
                return;
            } else {
                iX = abstractC1047f0.X();
            }
        } while (iX == i);
        this.d = iX;
    }

    public void l(VA va) throws zzgzh {
        int iX;
        int iX2;
        boolean z = va instanceof PA;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        if (z) {
            PA pa = (PA) va;
            int i = this.b & 7;
            if (i != 0) {
                if (i != 2) {
                    throw new zzgzg();
                }
                int iP = abstractC1047f0.P() + abstractC1047f0.Y();
                do {
                    pa.e(abstractC1047f0.U());
                } while (abstractC1047f0.P() < iP);
                x(iP);
                return;
            }
            do {
                pa.e(abstractC1047f0.U());
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX2 = abstractC1047f0.X();
                }
            } while (iX2 == this.b);
        } else {
            int i2 = this.b & 7;
            if (i2 != 0) {
                if (i2 != 2) {
                    throw new zzgzg();
                }
                int iP2 = abstractC1047f0.P() + abstractC1047f0.Y();
                do {
                    va.add(Integer.valueOf(abstractC1047f0.U()));
                } while (abstractC1047f0.P() < iP2);
                x(iP2);
                return;
            }
            do {
                va.add(Integer.valueOf(abstractC1047f0.U()));
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX = abstractC1047f0.X();
                }
            } while (iX == this.b);
            iX2 = iX;
        }
        this.d = iX2;
    }

    public void m(VA va) throws zzgzh {
        int iX;
        int iX2;
        boolean z = va instanceof C1827aB;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        if (z) {
            C1827aB c1827aB = (C1827aB) va;
            int i = this.b & 7;
            if (i != 0) {
                if (i != 2) {
                    throw new zzgzg();
                }
                int iP = abstractC1047f0.P() + abstractC1047f0.Y();
                do {
                    c1827aB.e(abstractC1047f0.a0());
                } while (abstractC1047f0.P() < iP);
                x(iP);
                return;
            }
            do {
                c1827aB.e(abstractC1047f0.a0());
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX2 = abstractC1047f0.X();
                }
            } while (iX2 == this.b);
        } else {
            int i2 = this.b & 7;
            if (i2 != 0) {
                if (i2 != 2) {
                    throw new zzgzg();
                }
                int iP2 = abstractC1047f0.P() + abstractC1047f0.Y();
                do {
                    va.add(Long.valueOf(abstractC1047f0.a0()));
                } while (abstractC1047f0.P() < iP2);
                x(iP2);
                return;
            }
            do {
                va.add(Long.valueOf(abstractC1047f0.a0()));
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX = abstractC1047f0.X();
                }
            } while (iX == this.b);
            iX2 = iX;
        }
        this.d = iX2;
    }

    public void n(VA va, InterfaceC2562rB interfaceC2562rB, IA ia) throws zzgzh {
        int iX;
        int i = this.b;
        if ((i & 7) != 2) {
            throw new zzgzg();
        }
        do {
            OA oaZze = interfaceC2562rB.zze();
            w(oaZze, interfaceC2562rB, ia);
            interfaceC2562rB.a(oaZze);
            va.add(oaZze);
            AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
            if (abstractC1047f0.G() || this.d != 0) {
                return;
            } else {
                iX = abstractC1047f0.X();
            }
        } while (iX == i);
        this.d = iX;
    }

    public void o(VA va) throws zzgzh {
        int iX;
        int iX2;
        boolean z = va instanceof PA;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        if (z) {
            PA pa = (PA) va;
            int i = this.b & 7;
            if (i == 2) {
                int iY = abstractC1047f0.Y();
                z(iY);
                int iP = abstractC1047f0.P() + iY;
                do {
                    pa.e(abstractC1047f0.V());
                } while (abstractC1047f0.P() < iP);
                return;
            }
            if (i != 5) {
                throw new zzgzg();
            }
            do {
                pa.e(abstractC1047f0.V());
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX2 = abstractC1047f0.X();
                }
            } while (iX2 == this.b);
        } else {
            int i2 = this.b & 7;
            if (i2 == 2) {
                int iY2 = abstractC1047f0.Y();
                z(iY2);
                int iP2 = abstractC1047f0.P() + iY2;
                do {
                    va.add(Integer.valueOf(abstractC1047f0.V()));
                } while (abstractC1047f0.P() < iP2);
                return;
            }
            if (i2 != 5) {
                throw new zzgzg();
            }
            do {
                va.add(Integer.valueOf(abstractC1047f0.V()));
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX = abstractC1047f0.X();
                }
            } while (iX == this.b);
            iX2 = iX;
        }
        this.d = iX2;
    }

    public void p(VA va) throws zzgzh {
        int iX;
        int iX2;
        boolean z = va instanceof C1827aB;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        if (z) {
            C1827aB c1827aB = (C1827aB) va;
            int i = this.b & 7;
            if (i != 1) {
                if (i != 2) {
                    throw new zzgzg();
                }
                int iY = abstractC1047f0.Y();
                A(iY);
                int iP = abstractC1047f0.P() + iY;
                do {
                    c1827aB.e(abstractC1047f0.b0());
                } while (abstractC1047f0.P() < iP);
                return;
            }
            do {
                c1827aB.e(abstractC1047f0.b0());
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX2 = abstractC1047f0.X();
                }
            } while (iX2 == this.b);
        } else {
            int i2 = this.b & 7;
            if (i2 != 1) {
                if (i2 != 2) {
                    throw new zzgzg();
                }
                int iY2 = abstractC1047f0.Y();
                A(iY2);
                int iP2 = abstractC1047f0.P() + iY2;
                do {
                    va.add(Long.valueOf(abstractC1047f0.b0()));
                } while (abstractC1047f0.P() < iP2);
                return;
            }
            do {
                va.add(Long.valueOf(abstractC1047f0.b0()));
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX = abstractC1047f0.X();
                }
            } while (iX == this.b);
            iX2 = iX;
        }
        this.d = iX2;
    }

    public void q(VA va) throws zzgzh {
        int iX;
        int iX2;
        boolean z = va instanceof PA;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        if (z) {
            PA pa = (PA) va;
            int i = this.b & 7;
            if (i != 0) {
                if (i != 2) {
                    throw new zzgzg();
                }
                int iP = abstractC1047f0.P() + abstractC1047f0.Y();
                do {
                    pa.e(abstractC1047f0.W());
                } while (abstractC1047f0.P() < iP);
                x(iP);
                return;
            }
            do {
                pa.e(abstractC1047f0.W());
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX2 = abstractC1047f0.X();
                }
            } while (iX2 == this.b);
        } else {
            int i2 = this.b & 7;
            if (i2 != 0) {
                if (i2 != 2) {
                    throw new zzgzg();
                }
                int iP2 = abstractC1047f0.P() + abstractC1047f0.Y();
                do {
                    va.add(Integer.valueOf(abstractC1047f0.W()));
                } while (abstractC1047f0.P() < iP2);
                x(iP2);
                return;
            }
            do {
                va.add(Integer.valueOf(abstractC1047f0.W()));
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX = abstractC1047f0.X();
                }
            } while (iX == this.b);
            iX2 = iX;
        }
        this.d = iX2;
    }

    public void r(VA va) throws zzgzh {
        int iX;
        int iX2;
        boolean z = va instanceof C1827aB;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        if (z) {
            C1827aB c1827aB = (C1827aB) va;
            int i = this.b & 7;
            if (i != 0) {
                if (i != 2) {
                    throw new zzgzg();
                }
                int iP = abstractC1047f0.P() + abstractC1047f0.Y();
                do {
                    c1827aB.e(abstractC1047f0.c0());
                } while (abstractC1047f0.P() < iP);
                x(iP);
                return;
            }
            do {
                c1827aB.e(abstractC1047f0.c0());
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX2 = abstractC1047f0.X();
                }
            } while (iX2 == this.b);
        } else {
            int i2 = this.b & 7;
            if (i2 != 0) {
                if (i2 != 2) {
                    throw new zzgzg();
                }
                int iP2 = abstractC1047f0.P() + abstractC1047f0.Y();
                do {
                    va.add(Long.valueOf(abstractC1047f0.c0()));
                } while (abstractC1047f0.P() < iP2);
                x(iP2);
                return;
            }
            do {
                va.add(Long.valueOf(abstractC1047f0.c0()));
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX = abstractC1047f0.X();
                }
            } while (iX == this.b);
            iX2 = iX;
        }
        this.d = iX2;
    }

    public void s(VA va, boolean z) throws zzgzg {
        String strF0;
        int iX;
        if ((this.b & 7) != 2) {
            throw new zzgzg();
        }
        do {
            AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
            if (z) {
                y(2);
                strF0 = abstractC1047f0.g0();
            } else {
                y(2);
                strF0 = abstractC1047f0.f0();
            }
            va.add(strF0);
            if (abstractC1047f0.G()) {
                return;
            } else {
                iX = abstractC1047f0.X();
            }
        } while (iX == this.b);
        this.d = iX;
    }

    public void t(VA va) throws zzgzh {
        int iX;
        int iX2;
        boolean z = va instanceof PA;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        if (z) {
            PA pa = (PA) va;
            int i = this.b & 7;
            if (i != 0) {
                if (i != 2) {
                    throw new zzgzg();
                }
                int iP = abstractC1047f0.P() + abstractC1047f0.Y();
                do {
                    pa.e(abstractC1047f0.Y());
                } while (abstractC1047f0.P() < iP);
                x(iP);
                return;
            }
            do {
                pa.e(abstractC1047f0.Y());
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX2 = abstractC1047f0.X();
                }
            } while (iX2 == this.b);
        } else {
            int i2 = this.b & 7;
            if (i2 != 0) {
                if (i2 != 2) {
                    throw new zzgzg();
                }
                int iP2 = abstractC1047f0.P() + abstractC1047f0.Y();
                do {
                    va.add(Integer.valueOf(abstractC1047f0.Y()));
                } while (abstractC1047f0.P() < iP2);
                x(iP2);
                return;
            }
            do {
                va.add(Integer.valueOf(abstractC1047f0.Y()));
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX = abstractC1047f0.X();
                }
            } while (iX == this.b);
            iX2 = iX;
        }
        this.d = iX2;
    }

    public String toString() {
        switch (this.a) {
            case 1:
                return "";
            default:
                return super.toString();
        }
    }

    public void u(VA va) throws zzgzh {
        int iX;
        int iX2;
        boolean z = va instanceof C1827aB;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        if (z) {
            C1827aB c1827aB = (C1827aB) va;
            int i = this.b & 7;
            if (i != 0) {
                if (i != 2) {
                    throw new zzgzg();
                }
                int iP = abstractC1047f0.P() + abstractC1047f0.Y();
                do {
                    c1827aB.e(abstractC1047f0.d0());
                } while (abstractC1047f0.P() < iP);
                x(iP);
                return;
            }
            do {
                c1827aB.e(abstractC1047f0.d0());
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX2 = abstractC1047f0.X();
                }
            } while (iX2 == this.b);
        } else {
            int i2 = this.b & 7;
            if (i2 != 0) {
                if (i2 != 2) {
                    throw new zzgzg();
                }
                int iP2 = abstractC1047f0.P() + abstractC1047f0.Y();
                do {
                    va.add(Long.valueOf(abstractC1047f0.d0()));
                } while (abstractC1047f0.P() < iP2);
                x(iP2);
                return;
            }
            do {
                va.add(Long.valueOf(abstractC1047f0.d0()));
                if (abstractC1047f0.G()) {
                    return;
                } else {
                    iX = abstractC1047f0.X();
                }
            } while (iX == this.b);
            iX2 = iX;
        }
        this.d = iX2;
    }

    public void v(Object obj, InterfaceC2562rB interfaceC2562rB, IA ia) {
        int i = this.c;
        this.c = ((this.b >>> 3) << 3) | 4;
        try {
            interfaceC2562rB.i(obj, this, ia);
            if (this.b == this.c) {
            } else {
                throw new zzgzh("Failed to parse the message.");
            }
        } finally {
            this.c = i;
        }
    }

    public void w(Object obj, InterfaceC2562rB interfaceC2562rB, IA ia) throws zzgzh {
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.e;
        int iY = abstractC1047f0.Y();
        if (abstractC1047f0.a >= 100) {
            throw new zzgzh("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        int iR = abstractC1047f0.R(iY);
        abstractC1047f0.a++;
        interfaceC2562rB.i(obj, this, ia);
        abstractC1047f0.h0();
        abstractC1047f0.a--;
        abstractC1047f0.i0(iR);
    }

    public void x(int i) throws zzgzh {
        if (((AbstractC1047f0) this.e).P() != i) {
            throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
    }

    public void y(int i) {
        if ((this.b & 7) != i) {
            throw new zzgzg();
        }
    }

    public K(AbstractC1047f0 abstractC1047f0) {
        this.a = 2;
        this.d = 0;
        Charset charset = WA.a;
        if (abstractC1047f0 == null) {
            throw new NullPointerException("input");
        }
        this.e = abstractC1047f0;
        abstractC1047f0.b = this;
    }

    public K(int i, int i2) {
        this.a = 3;
        this.e = new com.google.firebase.crashlytics.internal.metadata.m[i];
        for (int i3 = 0; i3 < i; i3++) {
            ((com.google.firebase.crashlytics.internal.metadata.m[]) this.e)[i3] = new com.google.firebase.crashlytics.internal.metadata.m(((i2 + 4) * 17) + 1);
        }
        this.d = i2 * 17;
        this.c = i;
        this.b = -1;
    }

    public K(int i) {
        this.a = 5;
        int iNumberOfLeadingZeros = 1 << (32 - Integer.numberOfLeadingZeros(i - 1));
        this.b = iNumberOfLeadingZeros - 1;
        this.d = (int) (0.75f * iNumberOfLeadingZeros);
        this.e = new Object[iNumberOfLeadingZeros];
    }

    public K(L l) {
        this.a = 0;
        this.e = l;
    }
}
