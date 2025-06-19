package androidx.vectordrawable.graphics.drawable;

import android.graphics.drawable.Drawable;
import android.os.Handler;
import androidx.compose.runtime.L0;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c implements Drawable.Callback {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public final void invalidateDrawable(Drawable d) {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                ((f) obj).invalidateSelf();
                break;
            default:
                Intrinsics.checkNotNullParameter(d, "d");
                com.google.accompanist.drawablepainter.a aVar = (com.google.accompanist.drawablepainter.a) obj;
                ((L0) aVar.g).setValue(Integer.valueOf(((Number) ((L0) aVar.g).getValue()).intValue() + 1));
                Object obj2 = com.google.accompanist.drawablepainter.c.a;
                Drawable drawable = aVar.f;
                ((L0) aVar.h).setValue(new androidx.compose.ui.geometry.e((drawable.getIntrinsicWidth() < 0 || drawable.getIntrinsicHeight() < 0) ? 9205357640488583168L : T4.a(drawable.getIntrinsicWidth(), drawable.getIntrinsicHeight())));
                break;
        }
    }

    /* JADX WARN: Type inference failed for: r2v4, types: [java.lang.Object, kotlin.k] */
    @Override // android.graphics.drawable.Drawable.Callback
    public final void scheduleDrawable(Drawable d, Runnable what, long j) {
        switch (this.a) {
            case 0:
                ((f) this.b).scheduleSelf(what, j);
                break;
            default:
                Intrinsics.checkNotNullParameter(d, "d");
                Intrinsics.checkNotNullParameter(what, "what");
                ((Handler) com.google.accompanist.drawablepainter.c.a.getValue()).postAtTime(what, j);
                break;
        }
    }

    /* JADX WARN: Type inference failed for: r2v4, types: [java.lang.Object, kotlin.k] */
    @Override // android.graphics.drawable.Drawable.Callback
    public final void unscheduleDrawable(Drawable d, Runnable what) {
        switch (this.a) {
            case 0:
                ((f) this.b).unscheduleSelf(what);
                break;
            default:
                Intrinsics.checkNotNullParameter(d, "d");
                Intrinsics.checkNotNullParameter(what, "what");
                ((Handler) com.google.accompanist.drawablepainter.c.a.getValue()).removeCallbacks(what);
                break;
        }
    }
}
