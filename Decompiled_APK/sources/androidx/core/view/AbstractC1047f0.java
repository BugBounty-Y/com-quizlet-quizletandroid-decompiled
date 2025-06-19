package androidx.core.view;

import androidx.datastore.preferences.protobuf.C1100g;
import androidx.datastore.preferences.protobuf.InvalidProtocolBufferException;
import androidx.glance.appwidget.protobuf.C1194f;
import com.google.android.gms.internal.ads.AbstractC2676tx;
import com.google.android.gms.internal.ads.C2905zA;
import com.google.android.gms.internal.ads.CA;
import com.google.android.gms.internal.ads.zzgzh;
import com.google.protobuf.C4012f;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

/* renamed from: androidx.core.view.f0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1047f0 {
    public int a;
    public Object b;

    public AbstractC1047f0(int i) {
        this.a = i;
    }

    public static int I(int i) {
        return (i >>> 1) ^ (-(i & 1));
    }

    public static long J(long j) {
        return (j >>> 1) ^ (-(1 & j));
    }

    public static CA K(int i, byte[] bArr, int i2) {
        CA ca = new CA(i, bArr, i2);
        try {
            ca.R(i2);
            return ca;
        } catch (zzgzh e) {
            throw new IllegalArgumentException(e);
        }
    }

    public abstract String A();

    public abstract int B();

    public abstract int C();

    public abstract long D();

    public abstract boolean E(int i);

    public void F() {
        int iB;
        do {
            iB = B();
            if (iB == 0) {
                return;
            }
            int i = this.a;
            if (i >= 100) {
                throw new InvalidProtocolBufferException("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
            }
            this.a = i + 1;
            this.a--;
        } while (E(iB));
    }

    public abstract boolean G();

    public abstract boolean H();

    public abstract double L();

    public abstract int M();

    public abstract float N();

    public abstract int[] O(int[] iArr, int i);

    public abstract int P();

    public ByteBuffer Q(int i, byte[] bArr) {
        int[] iArrO = O(AbstractC2676tx.d(bArr), i);
        int[] iArr = (int[]) iArrO.clone();
        AbstractC2676tx.b(iArr);
        for (int i2 = 0; i2 < 16; i2++) {
            iArrO[i2] = iArrO[i2] + iArr[i2];
        }
        ByteBuffer byteBufferOrder = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
        byteBufferOrder.asIntBuffer().put(iArrO, 0, 16);
        return byteBufferOrder;
    }

    public abstract int R(int i);

    public abstract int S();

    public abstract int T();

    public abstract int U();

    public abstract int V();

    public abstract int W();

    public abstract int X();

    public abstract int Y();

    public abstract long Z();

    public abstract void a(int i);

    public abstract long a0();

    public abstract int b();

    public abstract long b0();

    public abstract boolean c();

    public abstract long c0();

    public abstract void d(m0 m0Var);

    public abstract long d0();

    public abstract void e();

    public abstract C2905zA e0();

    public abstract D0 f(D0 d0, List list);

    public abstract String f0();

    public abstract androidx.work.impl.model.e g(androidx.work.impl.model.e eVar);

    public abstract String g0();

    public abstract void h(int i);

    public abstract void h0();

    public abstract int i(int i);

    public abstract void i0(int i);

    public abstract boolean j();

    public abstract C1100g k();

    public abstract C1194f l();

    public abstract C4012f m();

    public abstract double n();

    public abstract int o();

    public abstract int p();

    public abstract long q();

    public abstract float r();

    public abstract int s();

    public abstract long t();

    public abstract int u();

    public abstract long v();

    public abstract int x();

    public abstract long y();

    public abstract String z();
}
