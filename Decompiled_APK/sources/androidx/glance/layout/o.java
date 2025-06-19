package androidx.glance.layout;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class o implements androidx.glance.o {
    public final n a;
    public final n b;
    public final n c;
    public final n d;
    public final n e;
    public final n f;

    public o(n nVar, n nVar2, n nVar3, n nVar4, n nVar5, n nVar6) {
        this.a = nVar;
        this.b = nVar2;
        this.c = nVar3;
        this.d = nVar4;
        this.e = nVar5;
        this.f = nVar6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return Intrinsics.b(this.a, oVar.a) && Intrinsics.b(this.b, oVar.b) && Intrinsics.b(this.c, oVar.c) && Intrinsics.b(this.d, oVar.d) && Intrinsics.b(this.e, oVar.e) && Intrinsics.b(this.f, oVar.f);
    }

    public final int hashCode() {
        return this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "PaddingModifier(left=" + this.a + ", start=" + this.b + ", top=" + this.c + ", right=" + this.d + ", end=" + this.e + ", bottom=" + this.f + ')';
    }

    public /* synthetic */ o(n nVar, n nVar2, n nVar3, n nVar4) {
        this(new n(DefinitionKt.NO_Float_VALUE, 3), nVar, nVar2, new n(DefinitionKt.NO_Float_VALUE, 3), nVar3, nVar4);
    }
}
