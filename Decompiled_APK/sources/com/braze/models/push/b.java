package com.braze.models.push;

import android.os.Bundle;
import com.braze.models.push.BrazeNotificationPayload;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class b implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ Bundle c;

    public /* synthetic */ b(int i, Bundle bundle, String str) {
        this.a = i;
        this.b = str;
        this.c = bundle;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeNotificationPayload.Companion.parseObjectAsInteger$lambda$5(this.b, this.c);
            case 1:
                return BrazeNotificationPayload.Companion.parseStringAsLong$lambda$7(this.b, this.c);
            case 2:
                return BrazeNotificationPayload.Companion.parseStringAsColorInt$lambda$13(this.b, this.c);
            case 3:
                return BrazeNotificationPayload.Companion.parseLong$lambda$10(this.b, this.c);
            case 4:
                return BrazeNotificationPayload.Companion.parseString$lambda$11(this.b, this.c);
            case 5:
                return BrazeNotificationPayload.Companion.parseStringAsBoolean$lambda$9(this.b, this.c);
            case 6:
                return BrazeNotificationPayload.Companion.parseNonBlankString$lambda$14(this.b, this.c);
            default:
                return BrazeNotificationPayload.Companion.parseStringAsInteger$lambda$3(this.b, this.c);
        }
    }
}
