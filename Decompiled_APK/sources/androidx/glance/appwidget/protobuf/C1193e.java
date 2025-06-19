package androidx.glance.appwidget.protobuf;

import androidx.compose.animation.d0;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;

/* renamed from: androidx.glance.appwidget.protobuf.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1193e extends C1194f {
    public final int e;
    public final int f;

    public C1193e(int i, byte[] bArr, int i2) {
        super(bArr);
        C1194f.b(i, i + i2, bArr.length);
        this.e = i;
        this.f = i2;
    }

    private void readObject(ObjectInputStream objectInputStream) throws IOException {
        throw new InvalidObjectException("BoundedByteStream instances are not to be serialized directly");
    }

    @Override // androidx.glance.appwidget.protobuf.C1194f
    public final byte a(int i) {
        int i2 = this.f;
        if (((i2 - (i + 1)) | i) >= 0) {
            return this.b[this.e + i];
        }
        if (i < 0) {
            throw new ArrayIndexOutOfBoundsException(android.support.v4.media.session.a.f(i, "Index < 0: "));
        }
        throw new ArrayIndexOutOfBoundsException(d0.p("Index > length: ", i, ", ", i2));
    }

    @Override // androidx.glance.appwidget.protobuf.C1194f
    public final int e() {
        return this.e;
    }

    @Override // androidx.glance.appwidget.protobuf.C1194f
    public final byte g(int i) {
        return this.b[this.e + i];
    }

    @Override // androidx.glance.appwidget.protobuf.C1194f
    public final int size() {
        return this.f;
    }

    public Object writeReplace() {
        byte[] bArr;
        int i = this.f;
        if (i == 0) {
            bArr = AbstractC1209v.b;
        } else {
            byte[] bArr2 = new byte[i];
            System.arraycopy(this.b, this.e, bArr2, 0, i);
            bArr = bArr2;
        }
        return new C1194f(bArr);
    }
}
