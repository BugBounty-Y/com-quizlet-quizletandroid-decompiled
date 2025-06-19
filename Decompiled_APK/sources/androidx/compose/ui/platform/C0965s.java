package androidx.compose.ui.platform;

import android.os.SystemClock;
import android.view.MotionEvent;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.ui.platform.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0965s extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0971v b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0965s(C0971v c0971v, int i) {
        super(0);
        this.a = i;
        this.b = c0971v;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        int actionMasked;
        switch (this.a) {
            case 0:
                C0971v c0971v = this.b;
                MotionEvent motionEvent = c0971v.x1;
                if (motionEvent != null && ((actionMasked = motionEvent.getActionMasked()) == 7 || actionMasked == 9)) {
                    c0971v.y1 = SystemClock.uptimeMillis();
                    c0971v.post(c0971v.B1);
                }
                return Unit.a;
            default:
                return this.b.get_viewTreeOwners();
        }
    }
}
