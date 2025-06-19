package androidx.compose.ui.platform;

import android.graphics.Rect;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModePromptView;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.platform.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class ViewTreeObserverOnGlobalLayoutListenerC0944h implements ViewTreeObserver.OnGlobalLayoutListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ View b;

    public /* synthetic */ ViewTreeObserverOnGlobalLayoutListenerC0944h(View view, int i) {
        this.a = i;
        this.b = view;
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final void onGlobalLayout() {
        View view = this.b;
        switch (this.a) {
            case 0:
                ((C0971v) view).G();
                break;
            case 1:
                int i = com.amazon.aps.ads.util.adview.b.a;
                com.amazon.aps.ads.util.adview.b this$0 = (com.amazon.aps.ads.util.adview.b) view;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                this$0.verifyIsVisible();
                break;
            case 2:
                int i2 = WriteModePromptView.W;
                WriteModePromptView writeModePromptView = (WriteModePromptView) view;
                if (writeModePromptView.getMeasuredHeight() != writeModePromptView.I) {
                    writeModePromptView.I = writeModePromptView.getMeasuredHeight();
                    ViewGroup.LayoutParams layoutParams = writeModePromptView.n.getLayoutParams();
                    layoutParams.height = (int) (writeModePromptView.getHeight() * 0.5d);
                    writeModePromptView.n.setLayoutParams(layoutParams);
                    break;
                }
                break;
            default:
                int i3 = com.quizlet.themes.q.b;
                Rect rect = new Rect();
                com.quizlet.themes.q qVar = (com.quizlet.themes.q) view;
                qVar.getWindowVisibleDisplayFrame(rect);
                qVar.setKeyboardHeight(qVar.getResources().getDisplayMetrics().heightPixels - rect.bottom);
                break;
        }
    }
}
