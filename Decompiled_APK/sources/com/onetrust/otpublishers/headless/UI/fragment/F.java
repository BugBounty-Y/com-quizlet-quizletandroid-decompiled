package com.onetrust.otpublishers.headless.UI.fragment;

import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class F extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ D b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ F(D d, int i) {
        super(1);
        this.a = i;
        this.b = d;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        D d = this.b;
        String vendorId = (String) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(vendorId, "vendorId");
                com.google.firebase.perf.logging.b bVar = D.D;
                d.U(vendorId, OTVendorListMode.IAB);
                break;
            case 1:
                Intrinsics.checkNotNullParameter(vendorId, "vendorId");
                com.google.firebase.perf.logging.b bVar2 = D.D;
                d.U(vendorId, OTVendorListMode.GOOGLE);
                break;
            default:
                Intrinsics.checkNotNullParameter(vendorId, "vendorId");
                com.google.firebase.perf.logging.b bVar3 = D.D;
                d.U(vendorId, OTVendorListMode.GENERAL);
                break;
        }
        return Unit.a;
    }
}
