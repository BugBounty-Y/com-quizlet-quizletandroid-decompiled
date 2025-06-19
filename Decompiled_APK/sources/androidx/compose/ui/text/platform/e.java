package androidx.compose.ui.text.platform;

import android.text.TextPaint;
import android.text.style.ClickableSpan;
import android.view.View;
import androidx.compose.ui.text.AbstractC1013n;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e extends ClickableSpan {
    public static final /* synthetic */ int c = 0;
    public final /* synthetic */ int a = 0;
    public final Object b;

    public e(Function0 listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.b = listener;
    }

    @Override // android.text.style.ClickableSpan
    public final void onClick(View view) {
        switch (this.a) {
            case 0:
                AbstractC1013n abstractC1013n = (AbstractC1013n) this.b;
                com.quizlet.features.infra.basestudy.ui.c cVarA = abstractC1013n.a();
                if (cVarA != null) {
                    cVarA.a(abstractC1013n);
                    break;
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(view, "view");
                ((Function0) this.b).invoke();
                break;
        }
    }

    @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public void updateDrawState(TextPaint paint) {
        switch (this.a) {
            case 1:
                Intrinsics.checkNotNullParameter(paint, "paint");
                super.updateDrawState(paint);
                paint.setUnderlineText(false);
                break;
            default:
                super.updateDrawState(paint);
                break;
        }
    }

    public e(AbstractC1013n abstractC1013n) {
        this.b = abstractC1013n;
    }
}
