package androidx.core.view;

import android.os.Build;
import android.view.View;
import android.view.Window;
import android.view.WindowInsetsController;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6;

/* loaded from: classes.dex */
public final class H0 {
    public final AbstractC3291w6 a;

    public H0(WindowInsetsController windowInsetsController) {
        if (Build.VERSION.SDK_INT >= 35) {
            this.a = new G0(windowInsetsController, new com.quizlet.data.repository.school.membership.a(windowInsetsController));
        } else {
            this.a = new F0(windowInsetsController, new com.quizlet.data.repository.school.membership.a(windowInsetsController));
        }
    }

    public H0(Window window, View view) {
        com.quizlet.data.repository.school.membership.a aVar = new com.quizlet.data.repository.school.membership.a(view);
        int i = Build.VERSION.SDK_INT;
        if (i >= 35) {
            this.a = new G0(window, aVar);
        } else if (i >= 30) {
            this.a = new F0(window, aVar);
        } else {
            this.a = new E0(window, aVar);
        }
    }
}
