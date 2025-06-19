package com.onetrust.otpublishers.headless.UI.viewmodel;

import android.app.Application;
import androidx.lifecycle.AbstractC1237a;
import androidx.lifecycle.Y;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3665l4;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import com.onetrust.otpublishers.headless.UI.DataModels.l;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e extends AbstractC1237a {
    public final com.onetrust.otpublishers.headless.Internal.Preferences.e c;
    public int d;
    public String e;
    public OTPublishersHeadlessSDK f;
    public OTVendorUtils g;
    public final Y h;
    public final Y i;
    public final Y j;
    public final Y k;
    public final Y l;
    public final Y m;
    public final Y n;
    public final Y o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(Application application, com.onetrust.otpublishers.headless.Internal.Preferences.e otSharedPreferenceUtils) {
        super(application);
        Intrinsics.checkNotNullParameter(application, "application");
        Intrinsics.checkNotNullParameter(otSharedPreferenceUtils, "otSharedPreferenceUtils");
        this.c = otSharedPreferenceUtils;
        this.e = "";
        this.h = new Y();
        this.i = new Y(OTVendorListMode.IAB);
        this.j = new Y();
        this.k = new Y(new LinkedHashMap());
        this.l = new Y(new LinkedHashMap());
        this.m = new Y();
        this.n = new Y();
        this.o = new Y();
    }

    public final String B() {
        String str = ((l) AbstractC3665l4.a(this.h)).a;
        if (str == null || str.length() == 0) {
            str = null;
        }
        return str == null ? this.d == 11 ? "#2F2F2F" : "#FFFFFF" : str;
    }

    public final boolean C() {
        return OTVendorListMode.IAB.equalsIgnoreCase((String) AbstractC3665l4.a(this.i));
    }

    /* JADX WARN: Removed duplicated region for block: B:105:0x0197  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0069  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00f8  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void D() {
        /*
            Method dump skipped, instructions count: 423
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.viewmodel.e.D():void");
    }
}
