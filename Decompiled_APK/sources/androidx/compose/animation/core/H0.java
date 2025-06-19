package androidx.compose.animation.core;

/* loaded from: classes.dex */
public final class H0 implements androidx.compose.runtime.G {
    public final /* synthetic */ int a;
    public final /* synthetic */ E0 b;

    public /* synthetic */ H0(E0 e0, int i) {
        this.a = i;
        this.b = e0;
    }

    @Override // androidx.compose.runtime.G
    public final void dispose() {
        switch (this.a) {
            case 0:
                E0 e0 = this.b;
                e0.j();
                e0.a.N();
                break;
            default:
                E0 e02 = this.b;
                e02.j();
                e02.a.N();
                break;
        }
    }
}
