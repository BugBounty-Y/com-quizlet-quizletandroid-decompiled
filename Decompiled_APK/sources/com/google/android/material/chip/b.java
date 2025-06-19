package com.google.android.material.chip;

import android.graphics.Typeface;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4;
import com.google.android.material.internal.m;
import com.google.android.material.internal.n;

/* loaded from: classes2.dex */
public final class b extends AbstractC3448e4 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void g(int i) {
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4
    public final void e(int i) {
        switch (this.a) {
            case 0:
                break;
            default:
                n nVar = (n) this.b;
                nVar.e = true;
                m mVar = (m) nVar.f.get();
                if (mVar != null) {
                    mVar.a();
                    break;
                }
                break;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4
    public final void f(Typeface typeface, boolean z) {
        switch (this.a) {
            case 0:
                Chip chip = (Chip) this.b;
                f fVar = chip.e;
                chip.setText(fVar.N1 ? fVar.F : chip.getText());
                chip.requestLayout();
                chip.invalidate();
                break;
            default:
                if (!z) {
                    n nVar = (n) this.b;
                    nVar.e = true;
                    m mVar = (m) nVar.f.get();
                    if (mVar != null) {
                        mVar.a();
                        break;
                    }
                }
                break;
        }
    }
}
