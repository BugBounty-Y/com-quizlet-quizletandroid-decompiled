package androidx.compose.material3;

import android.window.OnBackInvokedCallback;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.material3.a2, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C0586a2 implements OnBackInvokedCallback {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;

    public /* synthetic */ C0586a2(int i, Function0 function0) {
        this.a = i;
        this.b = function0;
    }

    public final void onBackInvoked() {
        switch (this.a) {
            case 0:
                this.b.invoke();
                break;
            default:
                Function0 function0 = this.b;
                if (function0 != null) {
                    function0.invoke();
                    break;
                }
                break;
        }
    }
}
