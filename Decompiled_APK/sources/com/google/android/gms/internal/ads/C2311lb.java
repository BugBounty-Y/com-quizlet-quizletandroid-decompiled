package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.text.TextUtils;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.lb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2311lb extends Fi {
    public final Map d;
    public final Activity e;
    public final String f;
    public final long g;
    public final long h;
    public final String i;
    public final String j;

    public C2311lb(InterfaceC2529qe interfaceC2529qe, Map map) throws NumberFormatException {
        long j;
        super(9, interfaceC2529qe, "createCalendarEvent");
        this.d = map;
        this.e = interfaceC2529qe.zzi();
        this.f = E(OTUXParamsKeys.OT_UX_DESCRIPTION);
        this.i = E(OTUXParamsKeys.OT_UX_SUMMARY);
        String str = (String) map.get("start_ticks");
        long j2 = -1;
        if (str == null) {
            j = -1;
        } else {
            try {
                j = Long.parseLong(str);
            } catch (NumberFormatException unused) {
            }
        }
        this.g = j;
        String str2 = (String) this.d.get("end_ticks");
        if (str2 != null) {
            try {
                j2 = Long.parseLong(str2);
            } catch (NumberFormatException unused2) {
            }
        }
        this.h = j2;
        this.j = E("location");
    }

    public final String E(String str) {
        Map map = this.d;
        return TextUtils.isEmpty((CharSequence) map.get(str)) ? "" : (String) map.get(str);
    }
}
