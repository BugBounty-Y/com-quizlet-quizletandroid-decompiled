package androidx.datastore.preferences.protobuf;

import androidx.glance.appwidget.protobuf.C1194f;
import com.google.android.gms.internal.measurement.O1;
import com.google.android.gms.internal.play_billing.U0;
import com.google.protobuf.C4012f;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* renamed from: androidx.datastore.preferences.protobuf.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1097d implements Iterator {
    public final /* synthetic */ int a = 0;
    public int b = 0;
    public final int c;
    public final /* synthetic */ Object d;

    public C1097d(com.google.android.gms.internal.fido.T t) {
        this.d = t;
        this.c = t.e();
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                if (this.b < this.c) {
                }
                break;
            case 1:
                if (this.b < this.c) {
                }
                break;
            case 2:
                if (this.b < this.c) {
                }
                break;
            case 3:
                if (this.b < this.c) {
                }
                break;
            case 4:
                if (this.b < this.c) {
                }
                break;
            default:
                if (this.b < this.c) {
                }
                break;
        }
        return false;
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                int i = this.b;
                if (i >= this.c) {
                    throw new NoSuchElementException();
                }
                this.b = i + 1;
                return Byte.valueOf(((C1100g) this.d).h(i));
            case 1:
                int i2 = this.b;
                if (i2 >= this.c) {
                    throw new NoSuchElementException();
                }
                this.b = i2 + 1;
                return Byte.valueOf(((C1194f) this.d).g(i2));
            case 2:
                int i3 = this.b;
                if (i3 >= this.c) {
                    throw new NoSuchElementException();
                }
                this.b = i3 + 1;
                return Byte.valueOf(((com.google.android.gms.internal.fido.T) this.d).b(i3));
            case 3:
                int i4 = this.b;
                if (i4 >= this.c) {
                    throw new NoSuchElementException();
                }
                this.b = i4 + 1;
                return Byte.valueOf(((O1) this.d).b(i4));
            case 4:
                int i5 = this.b;
                if (i5 >= this.c) {
                    throw new NoSuchElementException();
                }
                this.b = i5 + 1;
                return Byte.valueOf(((U0) this.d).b(i5));
            default:
                int i6 = this.b;
                if (i6 >= this.c) {
                    throw new NoSuchElementException();
                }
                this.b = i6 + 1;
                return Byte.valueOf(((C4012f) this.d).g(i6));
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException();
            case 1:
                throw new UnsupportedOperationException();
            case 2:
                throw new UnsupportedOperationException();
            case 3:
                throw new UnsupportedOperationException();
            case 4:
                throw new UnsupportedOperationException();
            default:
                throw new UnsupportedOperationException();
        }
    }

    public C1097d(O1 o1) {
        this.d = o1;
        this.c = o1.c();
    }

    public C1097d(U0 u0) {
        this.d = u0;
        this.c = u0.c();
    }

    public C1097d(C4012f c4012f) {
        this.d = c4012f;
        this.c = c4012f.size();
    }

    public C1097d(C1100g c1100g) {
        this.d = c1100g;
        this.c = c1100g.size();
    }

    public C1097d(C1194f c1194f) {
        this.d = c1194f;
        this.c = c1194f.size();
    }
}
