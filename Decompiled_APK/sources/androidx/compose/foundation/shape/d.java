package androidx.compose.foundation.shape;

import androidx.compose.ui.graphics.L;
import androidx.compose.ui.graphics.M;
import androidx.compose.ui.graphics.N;
import androidx.compose.ui.graphics.V;
import androidx.compose.ui.unit.k;
import com.google.android.gms.internal.mlkit_vision_barcode.O4;
import com.google.android.gms.internal.mlkit_vision_barcode.R4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d implements V {
    public final a a;
    public final a b;
    public final a c;
    public final a d;

    public d(a aVar, a aVar2, a aVar3, a aVar4) {
        this.a = aVar;
        this.b = aVar2;
        this.c = aVar3;
        this.d = aVar4;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v2, types: [androidx.compose.foundation.shape.a] */
    /* JADX WARN: Type inference failed for: r3v2, types: [androidx.compose.foundation.shape.a] */
    public static d a(d dVar, b bVar, b bVar2, b bVar3, int i) {
        b bVar4 = bVar;
        if ((i & 1) != 0) {
            bVar4 = dVar.a;
        }
        a aVar = dVar.b;
        b bVar5 = bVar2;
        if ((i & 4) != 0) {
            bVar5 = dVar.c;
        }
        dVar.getClass();
        return new d(bVar4, aVar, bVar5, bVar3);
    }

    @Override // androidx.compose.ui.graphics.V
    public final N e(long j, k kVar, androidx.compose.ui.unit.b bVar) {
        float fA = this.a.a(j, bVar);
        float fA2 = this.b.a(j, bVar);
        float fA3 = this.c.a(j, bVar);
        float fA4 = this.d.a(j, bVar);
        float fC = androidx.compose.ui.geometry.e.c(j);
        float f = fA + fA4;
        if (f > fC) {
            float f2 = fC / f;
            fA *= f2;
            fA4 *= f2;
        }
        float f3 = fA2 + fA3;
        if (f3 > fC) {
            float f4 = fC / f3;
            fA2 *= f4;
            fA3 *= f4;
        }
        if (fA < DefinitionKt.NO_Float_VALUE || fA2 < DefinitionKt.NO_Float_VALUE || fA3 < DefinitionKt.NO_Float_VALUE || fA4 < DefinitionKt.NO_Float_VALUE) {
            throw new IllegalArgumentException(("Corner size in Px can't be negative(topStart = " + fA + ", topEnd = " + fA2 + ", bottomEnd = " + fA3 + ", bottomStart = " + fA4 + ")!").toString());
        }
        if (fA + fA2 + fA3 + fA4 == DefinitionKt.NO_Float_VALUE) {
            return new L(R4.a(0L, j));
        }
        androidx.compose.ui.geometry.c cVarA = R4.a(0L, j);
        k kVar2 = k.a;
        float f5 = kVar == kVar2 ? fA : fA2;
        long jA = O4.a(f5, f5);
        if (kVar == kVar2) {
            fA = fA2;
        }
        long jA2 = O4.a(fA, fA);
        float f6 = kVar == kVar2 ? fA3 : fA4;
        long jA3 = O4.a(f6, f6);
        if (kVar != kVar2) {
            fA4 = fA3;
        }
        return new M(new androidx.compose.ui.geometry.d(cVarA.a, cVarA.b, cVarA.c, cVarA.d, jA, jA2, jA3, O4.a(fA4, fA4)));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        if (!Intrinsics.b(this.a, dVar.a)) {
            return false;
        }
        if (!Intrinsics.b(this.b, dVar.b)) {
            return false;
        }
        if (Intrinsics.b(this.c, dVar.c)) {
            return Intrinsics.b(this.d, dVar.d);
        }
        return false;
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "RoundedCornerShape(topStart = " + this.a + ", topEnd = " + this.b + ", bottomEnd = " + this.c + ", bottomStart = " + this.d + ')';
    }
}
