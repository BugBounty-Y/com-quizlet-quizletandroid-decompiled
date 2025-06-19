package androidx.appcompat.app;

import android.view.ViewGroup;
import androidx.core.view.C1043d0;
import androidx.core.view.V;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class r implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ B b;

    public /* synthetic */ r(B b, int i) {
        this.a = i;
        this.b = b;
    }

    @Override // java.lang.Runnable
    public final void run() {
        ViewGroup viewGroup;
        switch (this.a) {
            case 0:
                B b = this.b;
                if ((b.j1 & 1) != 0) {
                    b.v(0);
                }
                if ((b.j1 & 4096) != 0) {
                    b.v(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY);
                }
                b.i1 = false;
                b.j1 = 0;
                break;
            default:
                B b2 = this.b;
                b2.w.showAtLocation(b2.v, 55, 0, 0);
                C1043d0 c1043d0 = b2.y;
                if (c1043d0 != null) {
                    c1043d0.b();
                }
                if (!(b2.z && (viewGroup = b2.A) != null && viewGroup.isLaidOut())) {
                    b2.v.setAlpha(1.0f);
                    b2.v.setVisibility(0);
                    break;
                } else {
                    b2.v.setAlpha(DefinitionKt.NO_Float_VALUE);
                    C1043d0 c1043d0A = V.a(b2.v);
                    c1043d0A.a(1.0f);
                    b2.y = c1043d0A;
                    c1043d0A.d(new C0062s(this, 0));
                    break;
                }
                break;
        }
    }
}
