package com.onetrust.otpublishers.headless.UI.fragment;

import android.content.res.Resources;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class E extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ D b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ E(D d, int i) {
        super(2);
        this.a = i;
        this.b = d;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) throws Resources.NotFoundException {
        int i = this.a;
        String id = (String) obj;
        boolean zBooleanValue = ((Boolean) obj2).booleanValue();
        switch (i) {
            case 0:
                Intrinsics.checkNotNullParameter(id, "id");
                D.T(this.b, id, zBooleanValue, OTVendorListMode.IAB);
                break;
            case 1:
                Intrinsics.checkNotNullParameter(id, "id");
                D.T(this.b, id, zBooleanValue, OTVendorListMode.GOOGLE);
                break;
            default:
                Intrinsics.checkNotNullParameter(id, "id");
                D.T(this.b, id, zBooleanValue, OTVendorListMode.GENERAL);
                break;
        }
        return Unit.a;
    }
}
