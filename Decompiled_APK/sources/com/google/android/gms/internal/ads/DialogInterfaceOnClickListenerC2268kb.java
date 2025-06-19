package com.google.android.gms.internal.ads;

import android.content.DialogInterface;
import android.content.Intent;
import android.provider.CalendarContract;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import org.json.JSONException;

/* renamed from: com.google.android.gms.internal.ads.kb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class DialogInterfaceOnClickListenerC2268kb implements DialogInterface.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ C2311lb b;

    public /* synthetic */ DialogInterfaceOnClickListenerC2268kb(C2311lb c2311lb, int i) {
        this.a = i;
        this.b = c2311lb;
    }

    @Override // android.content.DialogInterface.OnClickListener
    public final void onClick(DialogInterface dialogInterface, int i) throws JSONException {
        switch (this.a) {
            case 0:
                C2311lb c2311lb = this.b;
                Intent data = new Intent("android.intent.action.EDIT").setData(CalendarContract.Events.CONTENT_URI);
                data.putExtra("title", c2311lb.f);
                data.putExtra("eventLocation", c2311lb.j);
                data.putExtra(OTUXParamsKeys.OT_UX_DESCRIPTION, c2311lb.i);
                long j = c2311lb.g;
                if (j > -1) {
                    data.putExtra("beginTime", j);
                }
                long j2 = c2311lb.h;
                if (j2 > -1) {
                    data.putExtra("endTime", j2);
                }
                data.setFlags(268435456);
                com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                com.google.android.gms.ads.internal.util.F.q(c2311lb.e, data);
                break;
            default:
                this.b.u("Operation denied by user.");
                break;
        }
    }
}
