package com.google.mlkit.common.sdkinternal;

import com.google.android.gms.common.Feature;

/* loaded from: classes2.dex */
public final /* synthetic */ class n implements com.google.android.gms.common.api.i {
    public final /* synthetic */ int a;
    public final /* synthetic */ Feature[] b;

    public /* synthetic */ n(Feature[] featureArr, int i) {
        this.a = i;
        this.b = featureArr;
    }

    @Override // com.google.android.gms.common.api.i
    public final Feature[] a() {
        Feature[] featureArr = this.b;
        switch (this.a) {
            case 0:
                Feature[] featureArr2 = h.a;
                break;
            default:
                Feature[] featureArr3 = h.a;
                break;
        }
        return featureArr;
    }
}
