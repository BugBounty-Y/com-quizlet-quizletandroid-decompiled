package androidx.appcompat.view;

import androidx.appcompat.widget.x1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3267t6;

/* loaded from: classes.dex */
public final class j extends AbstractC3267t6 {
    public final /* synthetic */ int b;
    public boolean c;
    public int d;
    public final /* synthetic */ Object e;

    public j(k kVar) {
        this.b = 0;
        this.e = kVar;
        this.c = false;
        this.d = 0;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3267t6, androidx.core.view.InterfaceC1045e0
    public void a() {
        switch (this.b) {
            case 1:
                this.c = true;
                break;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3267t6, androidx.core.view.InterfaceC1045e0
    public final void b() {
        switch (this.b) {
            case 0:
                if (!this.c) {
                    this.c = true;
                    AbstractC3267t6 abstractC3267t6 = ((k) this.e).d;
                    if (abstractC3267t6 != null) {
                        abstractC3267t6.b();
                        break;
                    }
                }
                break;
            default:
                ((x1) this.e).a.setVisibility(0);
                break;
        }
    }

    @Override // androidx.core.view.InterfaceC1045e0
    public final void c() {
        switch (this.b) {
            case 0:
                int i = this.d + 1;
                this.d = i;
                k kVar = (k) this.e;
                if (i == kVar.a.size()) {
                    AbstractC3267t6 abstractC3267t6 = kVar.d;
                    if (abstractC3267t6 != null) {
                        abstractC3267t6.c();
                    }
                    this.d = 0;
                    this.c = false;
                    kVar.e = false;
                    break;
                }
                break;
            default:
                if (!this.c) {
                    ((x1) this.e).a.setVisibility(this.d);
                    break;
                }
                break;
        }
    }

    public j(x1 x1Var, int i) {
        this.b = 1;
        this.e = x1Var;
        this.d = i;
        this.c = false;
    }
}
