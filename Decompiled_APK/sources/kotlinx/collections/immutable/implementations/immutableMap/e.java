package kotlinx.collections.immutable.implementations.immutableMap;

import androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.o;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import java.util.ConcurrentModificationException;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;

/* loaded from: classes3.dex */
public class e extends androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.d {
    public final d e;
    public Object f;
    public boolean g;
    public int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(d builder, o[] path) {
        super(builder.c, path);
        Intrinsics.checkNotNullParameter(builder, "builder");
        Intrinsics.checkNotNullParameter(path, "path");
        this.e = builder;
        this.h = builder.e;
    }

    public final void f(int i, j jVar, Object obj, int i2, int i3, boolean z) {
        int i4;
        int i5 = i2 * 5;
        o[] oVarArr = (o[]) this.d;
        if (i5 <= 30) {
            int iD = 1 << AbstractC3417z1.d(i, i5);
            if (!jVar.i(iD)) {
                int iT = jVar.t(iD);
                j jVarS = jVar.s(iT);
                o oVar = oVarArr[i2];
                Object[] buffer = jVar.d;
                int iBitCount = Integer.bitCount(jVar.a) * 2;
                oVar.getClass();
                Intrinsics.checkNotNullParameter(buffer, "buffer");
                oVar.b = buffer;
                oVar.c = iBitCount;
                oVar.d = iT;
                f(i, jVarS, obj, i2 + 1, i3, z);
                return;
            }
            int iF = jVar.f(iD);
            if (iD != (z ? 1 << AbstractC3417z1.d(i3, i5) : 0) || i2 >= (i4 = this.b)) {
                o oVar2 = oVarArr[i2];
                Object[] buffer2 = jVar.d;
                int iBitCount2 = Integer.bitCount(jVar.a) * 2;
                oVar2.getClass();
                Intrinsics.checkNotNullParameter(buffer2, "buffer");
                oVar2.b = buffer2;
                oVar2.c = iBitCount2;
                oVar2.d = iF;
                this.b = i2;
                return;
            }
            o oVar3 = oVarArr[i4];
            Object[] objArr = jVar.d;
            Object[] buffer3 = {objArr[iF], objArr[iF + 1]};
            oVar3.getClass();
            Intrinsics.checkNotNullParameter(buffer3, "buffer");
            Intrinsics.checkNotNullParameter(buffer3, "buffer");
            oVar3.b = buffer3;
            oVar3.c = 2;
            oVar3.d = 0;
            return;
        }
        o oVar4 = oVarArr[i2];
        Object[] buffer4 = jVar.d;
        int length = buffer4.length;
        oVar4.getClass();
        Intrinsics.checkNotNullParameter(buffer4, "buffer");
        oVar4.b = buffer4;
        oVar4.c = length;
        oVar4.d = 0;
        while (true) {
            o oVar5 = oVarArr[i2];
            if (Intrinsics.b(oVar5.b[oVar5.d], obj)) {
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
        e eVar;
        if (!this.g) {
            throw new IllegalStateException();
        }
        boolean z = this.c;
        d dVar = this.e;
        if (!z) {
            eVar = this;
            O.c(dVar).remove(eVar.f);
        } else {
            if (!z) {
                throw new NoSuchElementException();
            }
            o oVar = ((o[]) this.d)[this.b];
            Object obj = oVar.b[oVar.d];
            O.c(dVar).remove(this.f);
            int iHashCode = obj != null ? obj.hashCode() : 0;
            j jVar = dVar.c;
            Object obj2 = this.f;
            eVar = this;
            eVar.f(iHashCode, jVar, obj, 0, obj2 != null ? obj2.hashCode() : 0, true);
        }
        eVar.f = null;
        eVar.g = false;
        eVar.h = dVar.e;
    }
}
