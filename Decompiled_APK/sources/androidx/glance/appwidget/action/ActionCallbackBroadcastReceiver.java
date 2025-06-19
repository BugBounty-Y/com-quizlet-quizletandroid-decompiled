package androidx.glance.appwidget.action;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3251r7;
import kotlin.Metadata;
import kotlinx.coroutines.O;

@Metadata
/* loaded from: classes.dex */
public final class ActionCallbackBroadcastReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        AbstractC3251r7.b(this, O.a, new b(context, intent, null));
    }
}
