package com.appsflyer.internal;

/* loaded from: classes.dex */
public final class AFh1mSDK extends AFh1rSDK {
    public final AFe1mSDK toString;

    @Deprecated
    public AFh1mSDK() {
        this.toString = null;
    }

    @Override // com.appsflyer.internal.AFh1rSDK
    public final AFe1mSDK getCurrencyIso4217Code() {
        AFe1mSDK aFe1mSDK = this.toString;
        return aFe1mSDK != null ? aFe1mSDK : AFe1mSDK.CACHED_EVENT;
    }

    public AFh1mSDK(String str, byte[] bArr, String str2, AFe1mSDK aFe1mSDK) {
        super(null, str, Boolean.FALSE);
        this.getRevenue = str2;
        getCurrencyIso4217Code(bArr);
        this.toString = aFe1mSDK;
    }
}
