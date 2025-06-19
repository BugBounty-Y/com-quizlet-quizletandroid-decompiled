package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

import com.google.android.gms.internal.mlkit_vision_barcode.H4;
import java.util.ConcurrentModificationException;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;

/* loaded from: classes.dex */
public class f extends d {
    public final e e;
    public Object f;
    public boolean g;
    public int h;

    public f(e eVar, o[] oVarArr) {
        super(eVar.c, oVarArr);
        this.e = eVar;
        this.h = eVar.e;
    }

    public final void f(int i, n nVar, Object obj, int i2) {
        int i3 = i2 * 5;
        o[] oVarArr = (o[]) this.d;
        if (i3 <= 30) {
            int iF = 1 << H4.f(i, i3);
            if (nVar.h(iF)) {
                oVarArr[i2].a(Integer.bitCount(nVar.a) * 2, nVar.f(iF), nVar.d);
                this.b = i2;
                return;
            }
            int iT = nVar.t(iF);
            n nVarS = nVar.s(iT);
            oVarArr[i2].a(Integer.bitCount(nVar.a) * 2, iT, nVar.d);
            f(i, nVarS, obj, i2 + 1);
            return;
        }
        o oVar = oVarArr[i2];
        Object[] objArr = nVar.d;
        oVar.a(objArr.length, 0, objArr);
        while (true) {
            o oVar2 = oVarArr[i2];
            if (Intrinsics.b(oVar2.b[oVar2.d], obj)) {
                this.b = i2;
                return;
            } else {
                oVarArr[i2].d += 2;
            }
        }
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.d, java.util.Iterator
    public final Object next() {
        if (this.e.e != this.h) {
            throw new ConcurrentModificationException();
        }
        if (!this.c) {
            throw new NoSuchElementException();
        }
        o oVar = ((o[]) this.d)[this.b];
        this.f = oVar.b[oVar.d];
        this.g = true;
        return super.next();
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.d, java.util.Iterator
    public final void remove() {
        if (!this.g) {
            throw new IllegalStateException();
        }
        boolean z = this.c;
        e eVar = this.e;
        if (!z) {
            O.c(eVar).remove(this.f);
        } else {
            if (!z) {
                throw new NoSuchElementException();
            }
            o oVar = ((o[]) this.d)[this.b];
            Object obj = oVar.b[oVar.d];
            O.c(eVar).remove(this.f);
            f(obj != null ? obj.hashCode() : 0, eVar.c, obj, 0);
        }
        this.f = null;
        this.g = false;
        this.h = eVar.e;
    }
}
