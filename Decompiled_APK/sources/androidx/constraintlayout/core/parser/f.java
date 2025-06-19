package androidx.constraintlayout.core.parser;

import com.google.android.gms.internal.measurement.C2977d;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* loaded from: classes.dex */
public final class f implements Iterator {
    public final /* synthetic */ int a;
    public int b;
    public Iterable c;

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                if (this.b < ((g) this.c).e.size()) {
                }
                break;
            default:
                if (this.b < ((C2977d) this.c).e()) {
                }
                break;
        }
        return false;
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                d dVar = (d) ((g) this.c).e.get(this.b);
                this.b++;
                return dVar;
            default:
                int i = this.b;
                C2977d c2977d = (C2977d) this.c;
                if (i >= c2977d.e()) {
                    throw new NoSuchElementException(android.support.v4.media.session.a.f(this.b, "Out of bounds index: "));
                }
                int i2 = this.b;
                this.b = i2 + 1;
                return c2977d.i(i2);
        }
    }

    public f(C2977d c2977d) {
        this.a = 1;
        this.c = c2977d;
        this.b = 0;
    }
}
