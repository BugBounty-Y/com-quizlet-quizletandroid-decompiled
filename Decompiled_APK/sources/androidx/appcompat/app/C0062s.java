package androidx.appcompat.app;

import android.view.View;
import android.view.ViewGroup;
import android.widget.PopupWindow;
import androidx.core.view.V;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3267t6;
import java.util.WeakHashMap;

/* renamed from: androidx.appcompat.app.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0062s extends AbstractC3267t6 {
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    public /* synthetic */ C0062s(Object obj, int i) {
        this.b = i;
        this.c = obj;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3267t6, androidx.core.view.InterfaceC1045e0
    public void b() {
        Object obj = this.c;
        switch (this.b) {
            case 0:
                ((r) obj).b.v.setVisibility(0);
                break;
            case 1:
                B b = (B) obj;
                b.v.setVisibility(0);
                if (b.v.getParent() instanceof View) {
                    View view = (View) b.v.getParent();
                    WeakHashMap weakHashMap = V.a;
                    androidx.core.view.J.c(view);
                    break;
                }
                break;
        }
    }

    @Override // androidx.core.view.InterfaceC1045e0
    public final void c() {
        Object obj = this.c;
        switch (this.b) {
            case 0:
                B b = ((r) obj).b;
                b.v.setAlpha(1.0f);
                b.y.d(null);
                b.y = null;
                break;
            case 1:
                B b2 = (B) obj;
                b2.v.setAlpha(1.0f);
                b2.y.d(null);
                b2.y = null;
                break;
            default:
                androidx.compose.foundation.text.input.internal.u uVar = (androidx.compose.foundation.text.input.internal.u) obj;
                ((B) uVar.c).v.setVisibility(8);
                B b3 = (B) uVar.c;
                PopupWindow popupWindow = b3.w;
                if (popupWindow != null) {
                    popupWindow.dismiss();
                } else if (b3.v.getParent() instanceof View) {
                    View view = (View) b3.v.getParent();
                    WeakHashMap weakHashMap = V.a;
                    androidx.core.view.J.c(view);
                }
                b3.v.e();
                b3.y.d(null);
                b3.y = null;
                ViewGroup viewGroup = b3.A;
                WeakHashMap weakHashMap2 = V.a;
                androidx.core.view.J.c(viewGroup);
                break;
        }
    }
}
