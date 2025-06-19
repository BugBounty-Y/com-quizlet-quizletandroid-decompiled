package androidx.glance.appwidget;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3251r7;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class MyPackageReplacedReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        AbstractC3251r7.b(this, kotlinx.coroutines.O.a, new w0(context, null));
    }
}
