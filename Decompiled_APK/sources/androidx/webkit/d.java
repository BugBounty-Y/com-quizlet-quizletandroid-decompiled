package androidx.webkit;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.Objects;

/* loaded from: classes.dex */
public final class d {
    public final String a;
    public final int b;

    public d(String str) {
        this.a = str;
        this.b = 0;
    }

    public final String a() {
        int i = this.b;
        if (i == 0) {
            return this.a;
        }
        throw new IllegalStateException(AbstractC0147y.g(new StringBuilder("Wrong data accessor type detected. "), i != 0 ? i != 1 ? "Unknown" : "ArrayBuffer" : "String", " expected, but got ", "String"));
    }

    public d(byte[] bArr) {
        Objects.requireNonNull(bArr);
        this.a = null;
        this.b = 1;
    }
}
