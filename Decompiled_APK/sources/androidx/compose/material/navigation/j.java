package androidx.compose.material.navigation;

import androidx.navigation.B;
import androidx.navigation.C;
import androidx.navigation.W;
import androidx.navigation.compose.C1275h;
import androidx.navigation.compose.C1276i;
import kotlin.collections.L;
import kotlin.jvm.internal.C4950i;

/* loaded from: classes.dex */
public final class j extends C {
    public final /* synthetic */ int g = 0;
    public final androidx.compose.runtime.internal.d h;
    public final W i;

    public j(i iVar, androidx.compose.runtime.internal.d dVar) {
        super(iVar, "Create");
        this.i = iVar;
        this.h = dVar;
    }

    @Override // androidx.navigation.C
    public B a() {
        switch (this.g) {
            case 1:
                return (C1275h) super.a();
            default:
                return super.a();
        }
    }

    @Override // androidx.navigation.C
    public final B b() {
        switch (this.g) {
            case 0:
                return new b((i) this.i, this.h);
            default:
                return new C1275h((C1276i) this.i, this.h);
        }
    }

    public j(C1276i c1276i, C4950i c4950i, L l, androidx.compose.runtime.internal.d dVar) {
        super(c1276i, c4950i, l);
        this.i = c1276i;
        this.h = dVar;
    }
}
