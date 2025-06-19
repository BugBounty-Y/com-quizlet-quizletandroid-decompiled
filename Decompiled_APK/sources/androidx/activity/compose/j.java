package androidx.activity.compose;

import android.R;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.ui.platform.ComposeView;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;

/* loaded from: classes.dex */
public abstract class j {
    public static final ViewGroup.LayoutParams a = new ViewGroup.LayoutParams(-2, -2);

    public static void a(androidx.activity.s sVar, androidx.compose.runtime.internal.d dVar) {
        View childAt = ((ViewGroup) sVar.getWindow().getDecorView().findViewById(R.id.content)).getChildAt(0);
        ComposeView composeView = childAt instanceof ComposeView ? (ComposeView) childAt : null;
        if (composeView != null) {
            composeView.setParentCompositionContext(null);
            composeView.setContent(dVar);
            return;
        }
        ComposeView composeView2 = new ComposeView(sVar, null, 6);
        composeView2.setParentCompositionContext(null);
        composeView2.setContent(dVar);
        View decorView = sVar.getWindow().getDecorView();
        if (p0.f(decorView) == null) {
            p0.n(decorView, sVar);
        }
        if (p0.g(decorView) == null) {
            p0.o(decorView, sVar);
        }
        if (AbstractC3347h2.b(decorView) == null) {
            AbstractC3347h2.e(decorView, sVar);
        }
        sVar.setContentView(composeView2, a);
    }
}
