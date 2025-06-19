package androidx.compose.foundation;

import android.view.View;
import android.widget.Magnifier;

/* loaded from: classes.dex */
public final class G0 implements E0 {
    public static final G0 b = new G0(0);
    public static final G0 c = new G0(1);
    public final /* synthetic */ int a;

    public /* synthetic */ G0(int i) {
        this.a = i;
    }

    @Override // androidx.compose.foundation.E0
    public final boolean a() {
        switch (this.a) {
            case 0:
                return false;
            default:
                return true;
        }
    }

    @Override // androidx.compose.foundation.E0
    public final D0 b(View view, androidx.compose.ui.unit.b bVar) {
        switch (this.a) {
            case 0:
                return new F0(new Magnifier(view));
            default:
                return new H0(new Magnifier(view));
        }
    }
}
