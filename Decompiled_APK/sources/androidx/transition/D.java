package androidx.transition;

import android.os.Handler;
import com.quizlet.quizletandroid.ui.setcreation.views.OcrCardView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class D extends z {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ D(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.transition.z, androidx.transition.InterfaceC1419w
    public final void d(y transition) {
        switch (this.a) {
            case 0:
                ((y) this.b).G();
                transition.D(this);
                break;
            default:
                Intrinsics.checkNotNullParameter(transition, "transition");
                OcrCardView ocrCardView = (OcrCardView) this.b;
                ocrCardView.c.animate().setDuration(50L).scaleX(-0.1f).scaleY(-0.1f).start();
                new Handler().postDelayed(new com.google.firebase.crashlytics.internal.metadata.q(ocrCardView, 21), 350L);
                break;
        }
    }
}
