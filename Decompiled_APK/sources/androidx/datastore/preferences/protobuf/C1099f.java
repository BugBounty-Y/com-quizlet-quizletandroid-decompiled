package androidx.datastore.preferences.protobuf;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;

/* renamed from: androidx.datastore.preferences.protobuf.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1099f extends C1100g {
    public final int e;
    public final int f;

    public C1099f(int i, byte[] bArr, int i2) {
        super(bArr);
        C1100g.b(i, i + i2, bArr.length);
        this.e = i;
        this.f = i2;
    }

    private void readObject(ObjectInputStream objectInputStream) throws IOException {
        throw new InvalidObjectException("BoundedByteStream instances are not to be serialized directly");
    }

    @Override // androidx.datastore.preferences.protobuf.C1100g
    public final byte a(int i) {
        int i2 = this.f;
        if (((i2 - (i + 1)) | i) >= 0) {
            return this.b[this.e + i];
        }
        if (i < 0) {
            throw new ArrayIndexOutOfBoundsException(android.support.v4.media.session.a.f(i, "Index < 0: "));
        }
        throw new ArrayIndexOutOfBoundsException(androidx.compose.animation.d0.p("Index > length: ", i, ", ", i2));
    }

    @Override // androidx.datastore.preferences.protobuf.C1100g
    public final void e(int i, byte[] bArr) {
        System.arraycopy(this.b, this.e, bArr, 0, i);
    }

    @Override // androidx.datastore.preferences.protobuf.C1100g
    public final int g() {
        return this.e;
    }

    @Override // androidx.datastore.preferences.protobuf.C1100g
    public final byte h(int i) {
        return this.b[this.e + i];
    }

    @Override // androidx.datastore.preferences.protobuf.C1100g
    public final int size() {
        return this.f;
    }

    public Object writeReplace() {
        byte[] bArr;
        int size = size();
        if (size == 0) {
            bArr = AbstractC1115w.b;
        } else {
            byte[] bArr2 = new byte[size];
            e(size, bArr2);
            bArr = bArr2;
        }
        return new C1100g(bArr);
    }
}
