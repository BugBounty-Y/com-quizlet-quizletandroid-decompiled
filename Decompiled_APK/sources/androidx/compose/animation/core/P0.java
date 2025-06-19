package androidx.compose.animation.core;

/* loaded from: classes.dex */
public interface P0 extends Q0 {
    @Override // androidx.compose.animation.core.N0
    default long b(AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        return (u() + m()) * 1000000;
    }

    int m();

    int u();
}
