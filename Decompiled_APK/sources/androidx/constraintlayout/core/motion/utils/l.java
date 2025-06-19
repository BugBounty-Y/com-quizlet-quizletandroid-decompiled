package androidx.constraintlayout.core.motion.utils;

import com.google.android.gms.measurement.internal.J;
import java.io.IOException;
import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.C5072a;
import okhttp3.internal.http2.ConnectionShutdownException;
import okhttp3.internal.http2.StreamResetException;
import okhttp3.o;
import okhttp3.s;

/* loaded from: classes.dex */
public final class l {
    public final /* synthetic */ int a = 0;
    public int b;
    public int c;
    public int d;
    public Object e;
    public Object f;
    public Cloneable g;
    public Object h;
    public Object i;
    public Object j;

    public /* synthetic */ l() {
    }

    /* JADX WARN: Type inference failed for: r0v6, types: [int[], java.lang.Cloneable] */
    public void a(float f, int i) {
        int i2 = this.c;
        int[] iArr = (int[]) this.g;
        if (i2 >= iArr.length) {
            this.g = Arrays.copyOf(iArr, iArr.length * 2);
            float[] fArr = (float[]) this.i;
            this.i = Arrays.copyOf(fArr, fArr.length * 2);
        }
        int[] iArr2 = (int[]) this.g;
        int i3 = this.c;
        iArr2[i3] = i;
        float[] fArr2 = (float[]) this.i;
        this.c = i3 + 1;
        fArr2[i3] = f;
    }

    public void b(int i, int i2) {
        int i3 = this.b;
        int[] iArr = (int[]) this.e;
        if (i3 >= iArr.length) {
            this.e = Arrays.copyOf(iArr, iArr.length * 2);
            int[] iArr2 = (int[]) this.f;
            this.f = Arrays.copyOf(iArr2, iArr2.length * 2);
        }
        int[] iArr3 = (int[]) this.e;
        int i4 = this.b;
        iArr3[i4] = i;
        int[] iArr4 = (int[]) this.f;
        this.b = i4 + 1;
        iArr4[i4] = i2;
    }

    public void c(int i, String str) {
        int i2 = this.d;
        int[] iArr = (int[]) this.h;
        if (i2 >= iArr.length) {
            this.h = Arrays.copyOf(iArr, iArr.length * 2);
            String[] strArr = (String[]) this.j;
            this.j = (String[]) Arrays.copyOf(strArr, strArr.length * 2);
        }
        int[] iArr2 = (int[]) this.h;
        int i3 = this.d;
        iArr2[i3] = i;
        String[] strArr2 = (String[]) this.j;
        this.d = i3 + 1;
        strArr2[i3] = str;
    }

    /* JADX WARN: Removed duplicated region for block: B:187:0x03c7 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:32:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0092  */
    /* JADX WARN: Type inference failed for: r7v17, types: [java.lang.Object, java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public okhttp3.internal.connection.i d(int r17, int r18, int r19, boolean r20, boolean r21) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 1192
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.motion.utils.l.d(int, int, int, boolean, boolean):okhttp3.internal.connection.i");
    }

    public boolean e(s url) {
        Intrinsics.checkNotNullParameter(url, "url");
        s sVar = ((C5072a) this.f).h;
        return url.e == sVar.e && Intrinsics.b(url.d, sVar.d);
    }

    public void f(IOException e) {
        Intrinsics.checkNotNullParameter(e, "e");
        this.j = null;
        if ((e instanceof StreamResetException) && ((StreamResetException) e).a == okhttp3.internal.http2.a.REFUSED_STREAM) {
            this.b++;
        } else if (e instanceof ConnectionShutdownException) {
            this.c++;
        } else {
            this.d++;
        }
    }

    public String toString() {
        switch (this.a) {
            case 0:
                StringBuilder sb = new StringBuilder("TypedBundle{mCountInt=");
                sb.append(this.b);
                sb.append(", mCountFloat=");
                sb.append(this.c);
                sb.append(", mCountString=");
                return android.support.v4.media.session.a.r(sb, this.d, ", mCountBoolean=0}");
            default:
                return super.toString();
        }
    }

    public l(J connectionPool, C5072a address, okhttp3.internal.connection.g call) {
        o eventListener = o.c;
        Intrinsics.checkNotNullParameter(connectionPool, "connectionPool");
        Intrinsics.checkNotNullParameter(address, "address");
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(eventListener, "eventListener");
        this.e = connectionPool;
        this.f = address;
        this.g = call;
    }
}
