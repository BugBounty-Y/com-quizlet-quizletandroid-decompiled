package androidx.core.view;

import android.view.View;
import android.view.Window;
import android.view.WindowInsetsController;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6;

/* loaded from: classes.dex */
public class F0 extends AbstractC3291w6 {
    public final WindowInsetsController c;
    public final com.quizlet.data.repository.school.membership.a d;
    public final Window e;

    public F0(WindowInsetsController windowInsetsController, com.quizlet.data.repository.school.membership.a aVar) {
        this.c = windowInsetsController;
        this.d = aVar;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6
    public final void a() {
        ((androidx.appcompat.app.L) this.d.b).L();
        this.c.hide(0);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6
    public boolean b() {
        this.c.setSystemBarsAppearance(0, 0);
        return (this.c.getSystemBarsAppearance() & 8) != 0;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6
    public final void c(boolean z) {
        Window window = this.e;
        if (z) {
            if (window != null) {
                View decorView = window.getDecorView();
                decorView.setSystemUiVisibility(decorView.getSystemUiVisibility() | 16);
            }
            this.c.setSystemBarsAppearance(16, 16);
            return;
        }
        if (window != null) {
            View decorView2 = window.getDecorView();
            decorView2.setSystemUiVisibility(decorView2.getSystemUiVisibility() & (-17));
        }
        this.c.setSystemBarsAppearance(0, 16);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6
    public final void d(boolean z) {
        Window window = this.e;
        if (z) {
            if (window != null) {
                View decorView = window.getDecorView();
                decorView.setSystemUiVisibility(decorView.getSystemUiVisibility() | 8192);
            }
            this.c.setSystemBarsAppearance(8, 8);
            return;
        }
        if (window != null) {
            View decorView2 = window.getDecorView();
            decorView2.setSystemUiVisibility(decorView2.getSystemUiVisibility() & (-8193));
        }
        this.c.setSystemBarsAppearance(0, 8);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6
    public final void e() {
        ((androidx.appcompat.app.L) this.d.b).R();
        this.c.show(0);
    }

    public F0(Window window, com.quizlet.data.repository.school.membership.a aVar) {
        this(window.getInsetsController(), aVar);
        this.e = window;
    }
}
