package kotlin.collections.builders;

import androidx.core.view.I;
import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends I implements Iterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int e;

    public f(h map, int i) {
        this.e = i;
        Intrinsics.checkNotNullParameter(map, "map");
        this.d = map;
        this.b = -1;
        this.c = map.h;
        f();
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.e) {
            case 0:
                b();
                int i = this.a;
                h hVar = (h) this.d;
                if (i >= hVar.f) {
                    throw new NoSuchElementException();
                }
                this.a = i + 1;
                this.b = i;
                g gVar = new g(hVar, i);
                f();
                return gVar;
            case 1:
                b();
                int i2 = this.a;
                h hVar2 = (h) this.d;
                if (i2 >= hVar2.f) {
                    throw new NoSuchElementException();
                }
                this.a = i2 + 1;
                this.b = i2;
                Object obj = hVar2.a[i2];
                f();
                return obj;
            default:
                b();
                int i3 = this.a;
                h hVar3 = (h) this.d;
                if (i3 >= hVar3.f) {
                    throw new NoSuchElementException();
                }
                this.a = i3 + 1;
                this.b = i3;
                Object[] objArr = hVar3.b;
                Intrinsics.d(objArr);
                Object obj2 = objArr[this.b];
                f();
                return obj2;
        }
    }
}
