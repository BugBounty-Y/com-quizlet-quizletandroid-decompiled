package androidx.camera.core.impl;

import android.hardware.camera2.CaptureRequest;

/* renamed from: androidx.camera.core.impl.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0162c {
    public final String a;
    public final Class b;
    public final CaptureRequest.Key c;

    public C0162c(String str, Class cls, CaptureRequest.Key key) {
        if (str == null) {
            throw new NullPointerException("Null id");
        }
        this.a = str;
        if (cls == null) {
            throw new NullPointerException("Null valueClass");
        }
        this.b = cls;
        this.c = key;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C0162c)) {
            return false;
        }
        C0162c c0162c = (C0162c) obj;
        if (!this.a.equals(c0162c.a) || !this.b.equals(c0162c.b)) {
            return false;
        }
        CaptureRequest.Key key = c0162c.c;
        CaptureRequest.Key key2 = this.c;
        return key2 == null ? key == null : key2.equals(key);
    }

    public final int hashCode() {
        int iHashCode = (((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003;
        CaptureRequest.Key key = this.c;
        return iHashCode ^ (key == null ? 0 : key.hashCode());
    }

    public final String toString() {
        return "Option{id=" + this.a + ", valueClass=" + this.b + ", token=" + this.c + "}";
    }
}
