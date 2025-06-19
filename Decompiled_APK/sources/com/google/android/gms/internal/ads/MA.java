package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.io.IOException;
import java.util.List;

/* loaded from: classes2.dex */
public abstract class MA implements Cloneable {
    public final OA a;
    public OA b;

    public MA(OA oa) {
        this.a = oa;
        if (oa.r()) {
            throw new IllegalArgumentException("Default instance must be immutable.");
        }
        this.b = oa.n();
    }

    public static void f(int i, List list) {
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

    public final void b(byte[] bArr, IA ia) throws zzgzh {
        int length = bArr.length;
        e();
        try {
            C2305lB.c.a(this.b.getClass()).c(this.b, bArr, 0, length, new C2776wA(ia));
        } catch (zzgzh e) {
            throw e;
        } catch (IOException e2) {
            throw new RuntimeException("Reading from byte array should not throw IOException.", e2);
        } catch (IndexOutOfBoundsException unused) {
            throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
    }

    public final OA c() {
        OA oaD = d();
        oaD.getClass();
        if (OA.v(oaD, true)) {
            return oaD;
        }
        throw new zzhbh();
    }

    public final Object clone() {
        MA ma = (MA) this.a.s(5, null);
        ma.b = d();
        return ma;
    }

    public final OA d() {
        if (!this.b.r()) {
            return this.b;
        }
        OA oa = this.b;
        oa.getClass();
        C2305lB.c.a(oa.getClass()).a(oa);
        oa.j();
        return this.b;
    }

    public final void e() {
        if (this.b.r()) {
            return;
        }
        OA oaN = this.a.n();
        C2305lB.c.a(oaN.getClass()).b(oaN, this.b);
        this.b = oaN;
    }
}
