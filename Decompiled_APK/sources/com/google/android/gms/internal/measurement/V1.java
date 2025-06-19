package com.google.android.gms.internal.measurement;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.ads.C2776wA;
import java.io.IOException;
import java.util.List;

/* loaded from: classes2.dex */
public abstract class V1 implements Cloneable {
    public final W1 a;
    public W1 b;

    public V1(W1 w1) {
        this.a = w1;
        if (w1.l()) {
            throw new IllegalArgumentException("Default instance must be immutable.");
        }
        this.b = (W1) w1.m(4);
    }

    public static void b(int i, List list) {
        String strC = AbstractC0147y.c(list.size() - i, "Element at index ", " is null.");
        int size = list.size();
        while (true) {
            size--;
            if (size < i) {
                throw new NullPointerException(strC);
            }
            list.remove(size);
        }
    }

    /* renamed from: c, reason: merged with bridge method [inline-methods] */
    public final V1 clone() {
        V1 v1 = (V1) this.a.m(5);
        v1.b = g();
        return v1;
    }

    public final void d(W1 w1) {
        W1 w12 = this.a;
        if (w12.equals(w1)) {
            return;
        }
        if (!this.b.l()) {
            W1 w13 = (W1) w12.m(4);
            C3054s2.c.a(w13.getClass()).b(w13, this.b);
            this.b = w13;
        }
        W1 w14 = this.b;
        C3054s2.c.a(w14.getClass()).b(w14, w1);
    }

    public final void e(byte[] bArr, int i, Q1 q1) throws zzmm {
        if (!this.b.l()) {
            W1 w1 = (W1) this.a.m(4);
            C3054s2.c.a(w1.getClass()).b(w1, this.b);
            this.b = w1;
        }
        try {
            InterfaceC3069v2 interfaceC3069v2A = C3054s2.c.a(this.b.getClass());
            W1 w12 = this.b;
            C2776wA c2776wA = new C2776wA();
            q1.getClass();
            interfaceC3069v2A.h(w12, bArr, 0, i, c2776wA);
        } catch (zzmm e) {
            throw e;
        } catch (IOException e2) {
            throw new RuntimeException("Reading from byte array should not throw IOException.", e2);
        } catch (IndexOutOfBoundsException unused) {
            throw new zzmm("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
    }

    public final W1 f() {
        W1 w1G = g();
        w1G.getClass();
        boolean zC = true;
        byte bByteValue = ((Byte) w1G.m(1)).byteValue();
        if (bByteValue != 1) {
            if (bByteValue == 0) {
                zC = false;
            } else {
                zC = C3054s2.c.a(w1G.getClass()).c(w1G);
                w1G.m(2);
            }
        }
        if (zC) {
            return w1G;
        }
        throw new zzod("Message was missing required fields.  (Lite runtime could not determine which fields were missing).");
    }

    public final W1 g() {
        if (!this.b.l()) {
            return this.b;
        }
        W1 w1 = this.b;
        w1.getClass();
        C3054s2.c.a(w1.getClass()).a(w1);
        w1.i();
        return this.b;
    }

    public final void h() {
        if (this.b.l()) {
            return;
        }
        W1 w1 = (W1) this.a.m(4);
        C3054s2.c.a(w1.getClass()).b(w1, this.b);
        this.b = w1;
    }
}
