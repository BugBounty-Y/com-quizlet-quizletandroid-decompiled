package androidx.compose.foundation.layout;

/* renamed from: androidx.compose.foundation.layout.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0384f implements InterfaceC0394k {
    public final /* synthetic */ int a;

    @Override // androidx.compose.foundation.layout.InterfaceC0394k
    public final void b(androidx.compose.ui.unit.b bVar, int i, int[] iArr, int[] iArr2) {
        switch (this.a) {
            case 0:
                AbstractC0398m.c(i, iArr, iArr2, false);
                break;
            default:
                AbstractC0398m.b(iArr, iArr2, false);
                break;
        }
    }

    public final String toString() {
        switch (this.a) {
            case 0:
                return "Arrangement#Bottom";
            default:
                return "Arrangement#Top";
        }
    }
}
