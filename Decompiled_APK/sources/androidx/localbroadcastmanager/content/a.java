package androidx.localbroadcastmanager.content;

import android.content.BroadcastReceiver;
import android.content.IntentFilter;
import androidx.compose.ui.node.B;

/* loaded from: classes.dex */
public final class a {
    public final IntentFilter a;
    public final BroadcastReceiver b;
    public boolean c;
    public boolean d;

    public a(BroadcastReceiver broadcastReceiver, IntentFilter intentFilter) {
        this.a = intentFilter;
        this.b = broadcastReceiver;
    }

    public final String toString() {
        StringBuilder sbL = B.l(128, "Receiver{");
        sbL.append(this.b);
        sbL.append(" filter=");
        sbL.append(this.a);
        if (this.d) {
            sbL.append(" DEAD");
        }
        sbL.append("}");
        return sbL.toString();
    }
}
