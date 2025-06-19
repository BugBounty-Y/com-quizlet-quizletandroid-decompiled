package androidx.compose.foundation.layout;

/* renamed from: androidx.compose.foundation.layout.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0386g implements InterfaceC0390i {
    public final /* synthetic */ int a;
    public float b;

    public C0386g(int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = 0;
                break;
            case 2:
                this.b = 0;
                break;
            case 3:
                this.b = 0;
                break;
            case 4:
                break;
            default:
                this.b = 0;
                break;
        }
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0388h, androidx.compose.foundation.layout.InterfaceC0394k
    public float a() {
        switch (this.a) {
        }
        return this.b;
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0394k
    public void b(androidx.compose.ui.unit.b bVar, int i, int[] iArr, int[] iArr2) {
        switch (this.a) {
            case 0:
                AbstractC0398m.a(i, iArr, iArr2, false);
                break;
            case 1:
                AbstractC0398m.d(i, iArr, iArr2, false);
                break;
            case 2:
                AbstractC0398m.e(i, iArr, iArr2, false);
                break;
            default:
                AbstractC0398m.f(i, iArr, iArr2, false);
                break;
        }
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0388h
    public void c(androidx.compose.ui.unit.b bVar, int i, int[] iArr, androidx.compose.ui.unit.k kVar, int[] iArr2) {
        switch (this.a) {
            case 0:
                if (kVar != androidx.compose.ui.unit.k.a) {
                    AbstractC0398m.a(i, iArr, iArr2, true);
                    break;
                } else {
                    AbstractC0398m.a(i, iArr, iArr2, false);
                    break;
                }
            case 1:
                if (kVar != androidx.compose.ui.unit.k.a) {
                    AbstractC0398m.d(i, iArr, iArr2, true);
                    break;
                } else {
                    AbstractC0398m.d(i, iArr, iArr2, false);
                    break;
                }
            case 2:
                if (kVar != androidx.compose.ui.unit.k.a) {
                    AbstractC0398m.e(i, iArr, iArr2, true);
                    break;
                } else {
                    AbstractC0398m.e(i, iArr, iArr2, false);
                    break;
                }
            default:
                if (kVar != androidx.compose.ui.unit.k.a) {
                    AbstractC0398m.f(i, iArr, iArr2, true);
                    break;
                } else {
                    AbstractC0398m.f(i, iArr, iArr2, false);
                    break;
                }
        }
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return "Arrangement#Center";
            case 1:
                return "Arrangement#SpaceAround";
            case 2:
                return "Arrangement#SpaceBetween";
            case 3:
                return "Arrangement#SpaceEvenly";
            default:
                return super.toString();
        }
    }
}
