package androidx.recyclerview.widget;

import android.view.View;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.GD;
import java.util.Arrays;

/* loaded from: classes.dex */
public final class N {
    public final /* synthetic */ int a = 0;
    public int b;
    public boolean c;
    public boolean d;
    public int e;
    public Object f;

    public N(GD gd) {
        this.f = gd;
    }

    public void a() {
        this.e = this.c ? ((androidx.emoji2.text.g) this.f).g() : ((androidx.emoji2.text.g) this.f).k();
    }

    public void b(int i, View view) {
        if (this.c) {
            int iB = ((androidx.emoji2.text.g) this.f).b(view);
            androidx.emoji2.text.g gVar = (androidx.emoji2.text.g) this.f;
            this.e = (Integer.MIN_VALUE == gVar.a ? 0 : gVar.l() - gVar.a) + iB;
        } else {
            this.e = ((androidx.emoji2.text.g) this.f).e(view);
        }
        this.b = i;
    }

    public void c(int i, View view) {
        androidx.emoji2.text.g gVar = (androidx.emoji2.text.g) this.f;
        int iL = Integer.MIN_VALUE == gVar.a ? 0 : gVar.l() - gVar.a;
        if (iL >= 0) {
            b(i, view);
            return;
        }
        this.b = i;
        if (!this.c) {
            int iE = ((androidx.emoji2.text.g) this.f).e(view);
            int iK = iE - ((androidx.emoji2.text.g) this.f).k();
            this.e = iE;
            if (iK > 0) {
                int iG = (((androidx.emoji2.text.g) this.f).g() - Math.min(0, (((androidx.emoji2.text.g) this.f).g() - iL) - ((androidx.emoji2.text.g) this.f).b(view))) - (((androidx.emoji2.text.g) this.f).c(view) + iE);
                if (iG < 0) {
                    this.e -= Math.min(iK, -iG);
                    return;
                }
                return;
            }
            return;
        }
        int iG2 = (((androidx.emoji2.text.g) this.f).g() - iL) - ((androidx.emoji2.text.g) this.f).b(view);
        this.e = ((androidx.emoji2.text.g) this.f).g() - iG2;
        if (iG2 > 0) {
            int iC = this.e - ((androidx.emoji2.text.g) this.f).c(view);
            int iK2 = ((androidx.emoji2.text.g) this.f).k();
            int iMin = iC - (Math.min(((androidx.emoji2.text.g) this.f).e(view) - iK2, 0) + iK2);
            if (iMin < 0) {
                this.e = Math.min(iG2, -iMin) + this.e;
            }
        }
    }

    public void d() {
        this.b = -1;
        this.e = Integer.MIN_VALUE;
        this.c = false;
        this.d = false;
    }

    public void e(int i) {
        this.c = 1 == ((this.c ? 1 : 0) | i);
        this.b += i;
    }

    public void f(int i, byte[] bArr, int i2) {
        if (this.c) {
            int i3 = i2 - i;
            byte[] bArr2 = (byte[]) this.f;
            int length = bArr2.length;
            int i4 = this.e + i3;
            if (length < i4) {
                this.f = Arrays.copyOf(bArr2, i4 + i4);
            }
            System.arraycopy(bArr, i, (byte[]) this.f, this.e, i3);
            this.e += i3;
        }
    }

    public void g() {
        this.c = false;
        this.d = false;
    }

    public void h(int i) {
        AbstractC1795We.L(!this.c);
        boolean z = i == this.b;
        this.c = z;
        if (z) {
            this.e = 3;
            this.d = false;
        }
    }

    public boolean i(int i) {
        if (!this.c) {
            return false;
        }
        this.e -= i;
        this.c = false;
        this.d = true;
        return true;
    }

    public String toString() {
        switch (this.a) {
            case 0:
                StringBuilder sb = new StringBuilder("AnchorInfo{mPosition=");
                sb.append(this.b);
                sb.append(", mCoordinate=");
                sb.append(this.e);
                sb.append(", mLayoutFromEnd=");
                sb.append(this.c);
                sb.append(", mValid=");
                return android.support.v4.media.session.a.u(sb, this.d, '}');
            default:
                return super.toString();
        }
    }

    public N(int i) {
        this.b = i;
        byte[] bArr = new byte[131];
        this.f = bArr;
        bArr[2] = 1;
    }

    public N() {
        d();
    }
}
