package androidx.core.view;

import android.view.View;
import android.view.Window;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6;

/* loaded from: classes.dex */
public final class E0 extends AbstractC3291w6 {
    public final Window c;
    public final com.quizlet.data.repository.school.membership.a d;

    public E0(Window window, com.quizlet.data.repository.school.membership.a aVar) {
        this.c = window;
        this.d = aVar;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6
    public final void a() {
        for (int i = 1; i <= 512; i <<= 1) {
            if ((8 & i) != 0) {
                if (i == 1) {
                    f(4);
                } else if (i == 2) {
                    f(2);
                } else if (i == 8) {
                    ((androidx.appcompat.app.L) this.d.b).L();
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6
    public final boolean b() {
        return (this.c.getDecorView().getSystemUiVisibility() & 8192) != 0;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6
    public final void c(boolean z) {
        if (!z) {
            g(16);
            return;
        }
        Window window = this.c;
        window.clearFlags(134217728);
        window.addFlags(Integer.MIN_VALUE);
        f(16);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6
    public final void d(boolean z) {
        if (!z) {
            g(8192);
            return;
        }
        Window window = this.c;
        window.clearFlags(67108864);
        window.addFlags(Integer.MIN_VALUE);
        f(8192);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6
    public final void e() {
        for (int i = 1; i <= 512; i <<= 1) {
            if ((8 & i) != 0) {
                if (i == 1) {
                    g(4);
                    this.c.clearFlags(1024);
                } else if (i == 2) {
                    g(2);
                } else if (i == 8) {
                    ((androidx.appcompat.app.L) this.d.b).R();
                }
            }
        }
    }

    public final void f(int i) {
        View decorView = this.c.getDecorView();
        decorView.setSystemUiVisibility(i | decorView.getSystemUiVisibility());
    }

    public final void g(int i) {
        View decorView = this.c.getDecorView();
        decorView.setSystemUiVisibility((~i) & decorView.getSystemUiVisibility());
    }
}
