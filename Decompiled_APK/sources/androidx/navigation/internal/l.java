package androidx.navigation.internal;

import androidx.navigation.C1301x;
import com.braze.Braze;
import com.braze.BrazeUser;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class l implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    public /* synthetic */ l(String str, int i) {
        this.a = i;
        this.b = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                String uriPattern = this.b;
                Intrinsics.checkNotNullParameter(uriPattern, "uriPattern");
                return new C1301x(uriPattern);
            case 1:
                return Braze.changeUser$lambda$138$lambda$132(this.b);
            case 2:
                return Braze.changeUser$lambda$138$lambda$133(this.b);
            case 3:
                return Braze.changeUser$lambda$138$lambda$134(this.b);
            case 4:
                return Braze.changeUser$lambda$138$lambda$135(this.b);
            case 5:
                return Braze.changeUser$lambda$138$lambda$137(this.b);
            case 6:
                return Braze.logPurchase$lambda$51(this.b);
            case 7:
                return Braze._set_registeredPushToken_$lambda$36$lambda$33(this.b);
            case 8:
                return Braze._set_registeredPushToken_$lambda$36$lambda$35(this.b);
            case 9:
                return Braze.verifyProperSdkSetup$lambda$214(this.b);
            case 10:
                return Braze.logCustomEvent$lambda$44(this.b);
            case 11:
                return Braze.logPushDelivery$lambda$200(this.b);
            case 12:
                return Braze.changeUser$lambda$130(this.b);
            case 13:
                return Braze._set_registeredPushToken_$lambda$32(this.b);
            case 14:
                return Braze.logPushNotificationOpened$lambda$62$lambda$60(this.b);
            case 15:
                return BrazeUser.removeFromCustomAttributeArray$lambda$54(this.b);
            case 16:
                return BrazeUser.addToSubscriptionGroup$lambda$29(this.b);
            case 17:
                return BrazeUser.setCountry$lambda$20(this.b);
            case 18:
                return BrazeUser.setPhoneNumber$lambda$36$lambda$35(this.b);
            case 19:
                return BrazeUser.setLanguage$lambda$24(this.b);
            case 20:
                return BrazeUser.setFirstName$lambda$9(this.b);
            case 21:
                return BrazeUser.addToCustomAttributeArray$lambda$52(this.b);
            case EventType.WINDOW_STATE /* 22 */:
                return BrazeUser.setLastName$lambda$11(this.b);
            case EventType.AUDIO /* 23 */:
                return BrazeUser.setPhoneNumber$lambda$37(this.b);
            case EventType.VIDEO /* 24 */:
                return BrazeUser.setHomeCity$lambda$22(this.b);
            case EventType.SUBS /* 25 */:
                return BrazeUser.setLineId$lambda$41$lambda$40(this.b);
            case EventType.CDN /* 26 */:
                return BrazeUser.setLineId$lambda$42(this.b);
            case 27:
                return BrazeUser.addAlias$lambda$7(this.b);
            case 28:
                return BrazeUser.setCustomUserAttribute$lambda$47(this.b);
            default:
                return BrazeUser.setCustomUserAttribute$lambda$48(this.b);
        }
    }
}
