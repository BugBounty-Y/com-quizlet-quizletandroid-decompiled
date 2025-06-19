package com.airbnb.lottie.parser.moshi;

import java.io.Closeable;
import java.util.Arrays;

/* loaded from: classes.dex */
public abstract class d implements Closeable {
    public static final String[] e = new String[128];
    public int a;
    public int[] b;
    public String[] c;
    public int[] d;

    static {
        for (int i = 0; i <= 31; i++) {
            e[i] = String.format("\\u%04x", Integer.valueOf(i));
        }
        String[] strArr = e;
        strArr[34] = "\\\"";
        strArr[92] = "\\\\";
        strArr[9] = "\\t";
        strArr[8] = "\\b";
        strArr[10] = "\\n";
        strArr[13] = "\\r";
        strArr[12] = "\\f";
    }

    public abstract int B();

    public final void C(int i) {
        int i2 = this.a;
        int[] iArr = this.b;
        if (i2 == iArr.length) {
            if (i2 == 256) {
                throw new a("Nesting too deep at " + j(), 0);
            }
            this.b = Arrays.copyOf(iArr, iArr.length * 2);
            String[] strArr = this.c;
            this.c = (String[]) Arrays.copyOf(strArr, strArr.length * 2);
            int[] iArr2 = this.d;
            this.d = Arrays.copyOf(iArr2, iArr2.length * 2);
        }
        int[] iArr3 = this.b;
        int i3 = this.a;
        this.a = i3 + 1;
        iArr3[i3] = i;
    }

    public abstract int D(c cVar);

    public abstract void P();

    public abstract void Q();

    public final void Y(String str) throws b {
        StringBuilder sbX = android.support.v4.media.session.a.x(str, " at path ");
        sbX.append(j());
        throw new b(sbX.toString());
    }

    public abstract void a();

    public abstract void d();

    public abstract void f();

    public abstract void i();

    public final String j() {
        int i = this.a;
        int[] iArr = this.b;
        String[] strArr = this.c;
        int[] iArr2 = this.d;
        StringBuilder sb = new StringBuilder("$");
        for (int i2 = 0; i2 < i; i2++) {
            int i3 = iArr[i2];
            if (i3 == 1 || i3 == 2) {
                sb.append('[');
                sb.append(iArr2[i2]);
                sb.append(']');
            } else if (i3 == 3 || i3 == 4 || i3 == 5) {
                sb.append('.');
                String str = strArr[i2];
                if (str != null) {
                    sb.append(str);
                }
            }
        }
        return sb.toString();
    }

    public abstract boolean l();

    public abstract boolean p();

    public abstract double q();

    public abstract int r();

    public abstract String y();
}
