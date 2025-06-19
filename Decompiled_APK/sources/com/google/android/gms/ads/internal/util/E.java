package com.google.android.gms.ads.internal.util;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.ads.AbstractC1981ds;
import com.google.android.gms.internal.ads.Yr;
import com.google.android.gms.internal.mlkit_vision_common.Y2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3755x;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class E extends BroadcastReceiver {
    public final /* synthetic */ int a;

    public /* synthetic */ E(int i) {
        this.a = i;
    }

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        switch (this.a) {
            case 0:
                synchronized (com.google.android.gms.ads.internal.util.client.f.b) {
                    com.google.android.gms.ads.internal.util.client.f.c = false;
                    com.google.android.gms.ads.internal.util.client.f.d = false;
                    com.google.android.gms.ads.internal.util.client.i.h("Ad debug logging enablement is out of date.");
                }
                Y2.d(context);
                return;
            case 1:
                boolean zEquals = intent.getAction().equals("android.intent.action.SCREEN_OFF");
                Yr yr = Yr.d;
                if (zEquals) {
                    yr.a(true, yr.c);
                    yr.b = true;
                    return;
                } else {
                    if (intent.getAction().equals("android.intent.action.SCREEN_ON")) {
                        yr.a(false, yr.c);
                        yr.b = false;
                        return;
                    }
                    return;
                }
            case 2:
                if (intent.getAction() == "android.media.action.HDMI_AUDIO_PLUG") {
                    int intExtra = intent.getIntExtra("android.media.extra.AUDIO_PLUG_STATE", -1);
                    if (intExtra == 0) {
                        AbstractC1981ds.a = 1;
                        return;
                    } else {
                        if (intExtra == 1) {
                            AbstractC1981ds.a = 2;
                            return;
                        }
                        return;
                    }
                }
                return;
            case 3:
                if (intent.getAction() == "android.media.action.HDMI_AUDIO_PLUG") {
                    int intExtra2 = intent.getIntExtra("android.media.extra.AUDIO_PLUG_STATE", -1);
                    if (intExtra2 == 0) {
                        AbstractC3755x.a = 1;
                        return;
                    } else {
                        if (intExtra2 == 1) {
                            AbstractC3755x.a = 2;
                            return;
                        }
                        return;
                    }
                }
                return;
            case 4:
                if (intent.getAction() == "android.media.action.HDMI_AUDIO_PLUG") {
                    intent.getIntExtra("android.media.extra.AUDIO_PLUG_STATE", -1);
                    return;
                }
                return;
            default:
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(intent, "intent");
                return;
        }
    }
}
