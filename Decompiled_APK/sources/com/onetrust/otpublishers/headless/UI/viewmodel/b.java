package com.onetrust.otpublishers.headless.UI.viewmodel;

import android.app.Application;
import android.content.SharedPreferences;
import androidx.constraintlayout.motion.widget.n;
import androidx.lifecycle.AbstractC1237a;
import androidx.lifecycle.Y;
import androidx.navigation.internal.m;
import com.airbnb.lottie.animation.keyframe.q;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends AbstractC1237a {
    public final OTPublishersHeadlessSDK c;
    public final SharedPreferences d;
    public final Y e;
    public final Y f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(Application application, OTPublishersHeadlessSDK otPublishersHeadlessSDK, SharedPreferences otSharedPreference) {
        super(application);
        Intrinsics.checkNotNullParameter(application, "application");
        Intrinsics.checkNotNullParameter(otPublishersHeadlessSDK, "otPublishersHeadlessSDK");
        Intrinsics.checkNotNullParameter(otSharedPreference, "otSharedPreference");
        this.c = otPublishersHeadlessSDK;
        this.d = otSharedPreference;
        Y y = new Y();
        this.e = y;
        this.f = y;
    }

    public final String B() {
        q qVar;
        m mVar;
        Y y = this.e;
        com.onetrust.otpublishers.headless.UI.DataModels.a aVar = (com.onetrust.otpublishers.headless.UI.DataModels.a) y.d();
        String str = (aVar == null || (qVar = aVar.t) == null || (mVar = (m) qVar.i) == null) ? null : (String) mVar.b;
        if (str == null || str.length() == 0) {
            str = null;
        }
        if (str != null) {
            return str;
        }
        com.onetrust.otpublishers.headless.UI.DataModels.a aVar2 = (com.onetrust.otpublishers.headless.UI.DataModels.a) y.d();
        if (aVar2 != null) {
            return aVar2.h;
        }
        return null;
    }

    public final String C() {
        n nVar;
        Y y = this.e;
        com.onetrust.otpublishers.headless.UI.DataModels.a aVar = (com.onetrust.otpublishers.headless.UI.DataModels.a) y.d();
        String str = (aVar == null || (nVar = (n) aVar.t.m) == null) ? null : (String) nVar.f;
        if (str == null || str.length() == 0) {
            str = null;
        }
        if (str != null) {
            return str;
        }
        com.onetrust.otpublishers.headless.UI.DataModels.a aVar2 = (com.onetrust.otpublishers.headless.UI.DataModels.a) y.d();
        if (aVar2 != null) {
            return aVar2.g;
        }
        return null;
    }
}
