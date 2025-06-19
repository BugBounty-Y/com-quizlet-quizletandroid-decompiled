package com.google.android.gms.internal.ads;

import android.graphics.Color;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.util.ArrayList;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.n8, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2388n8 extends AbstractBinderC2602s8 {
    public static final int i;
    public static final int j;
    public final String a;
    public final ArrayList b;
    public final ArrayList c;
    public final int d;
    public final int e;
    public final int f;
    public final int g;
    public final int h;

    static {
        int iRgb = Color.rgb(12, 174, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SERVICE_SPECIFIC_OFF);
        i = Color.rgb(204, 204, 204);
        j = iRgb;
    }

    public BinderC2388n8(String str, List list, Integer num, Integer num2, Integer num3, int i2, int i3) {
        super("com.google.android.gms.ads.internal.formats.client.IAttributionInfo");
        this.b = new ArrayList();
        this.c = new ArrayList();
        this.a = str;
        for (int i4 = 0; i4 < list.size(); i4++) {
            BinderC2474p8 binderC2474p8 = (BinderC2474p8) list.get(i4);
            this.b.add(binderC2474p8);
            this.c.add(binderC2474p8);
        }
        this.d = num != null ? num.intValue() : i;
        this.e = num2 != null ? num2.intValue() : j;
        this.f = num3 != null ? num3.intValue() : 12;
        this.g = i2;
        this.h = i3;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2645t8
    public final ArrayList g() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2645t8
    public final String h() {
        return this.a;
    }
}
