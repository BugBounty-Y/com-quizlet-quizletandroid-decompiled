package androidx.camera.camera2.internal;

import android.util.Size;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0168g;
import java.util.ArrayList;

/* renamed from: androidx.camera.camera2.internal.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0125b {
    public final String a;
    public final Class b;
    public final androidx.camera.core.impl.q0 c;
    public final A0 d;
    public final Size e;
    public final C0168g f;
    public final ArrayList g;

    public C0125b(String str, Class cls, androidx.camera.core.impl.q0 q0Var, A0 a0, Size size, C0168g c0168g, ArrayList arrayList) {
        if (str == null) {
            throw new NullPointerException("Null useCaseId");
        }
        this.a = str;
        this.b = cls;
        if (q0Var == null) {
            throw new NullPointerException("Null sessionConfig");
        }
        this.c = q0Var;
        if (a0 == null) {
            throw new NullPointerException("Null useCaseConfig");
        }
        this.d = a0;
        this.e = size;
        this.f = c0168g;
        this.g = arrayList;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C0125b)) {
            return false;
        }
        C0125b c0125b = (C0125b) obj;
        if (!this.a.equals(c0125b.a) || !this.b.equals(c0125b.b) || !this.c.equals(c0125b.c) || !this.d.equals(c0125b.d)) {
            return false;
        }
        Size size = c0125b.e;
        Size size2 = this.e;
        if (size2 == null) {
            if (size != null) {
                return false;
            }
        } else if (!size2.equals(size)) {
            return false;
        }
        C0168g c0168g = c0125b.f;
        C0168g c0168g2 = this.f;
        if (c0168g2 == null) {
            if (c0168g != null) {
                return false;
            }
        } else if (!c0168g2.equals(c0168g)) {
            return false;
        }
        ArrayList arrayList = c0125b.g;
        ArrayList arrayList2 = this.g;
        return arrayList2 == null ? arrayList == null : arrayList2.equals(arrayList);
    }

    public final int hashCode() {
        int iHashCode = (((((((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003) ^ this.c.hashCode()) * 1000003) ^ this.d.hashCode()) * 1000003;
        Size size = this.e;
        int iHashCode2 = (iHashCode ^ (size == null ? 0 : size.hashCode())) * 1000003;
        C0168g c0168g = this.f;
        int iHashCode3 = (iHashCode2 ^ (c0168g == null ? 0 : c0168g.hashCode())) * 1000003;
        ArrayList arrayList = this.g;
        return iHashCode3 ^ (arrayList != null ? arrayList.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UseCaseInfo{useCaseId=");
        sb.append(this.a);
        sb.append(", useCaseType=");
        sb.append(this.b);
        sb.append(", sessionConfig=");
        sb.append(this.c);
        sb.append(", useCaseConfig=");
        sb.append(this.d);
        sb.append(", surfaceResolution=");
        sb.append(this.e);
        sb.append(", streamSpec=");
        sb.append(this.f);
        sb.append(", captureTypes=");
        return AbstractC0147y.f("}", sb, this.g);
    }
}
