package com.pubmatic.sdk.openwrap.banner;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.h;
import com.pubmatic.sdk.openwrap.core.f;
import java.util.Arrays;
import java.util.List;

/* loaded from: classes2.dex */
public class e extends a {
    private com.pubmatic.sdk.common.f[] a;
    private b b;

    public e(@NonNull com.pubmatic.sdk.common.f... fVarArr) {
        this.a = fVarArr;
    }

    @Override // com.pubmatic.sdk.openwrap.core.e
    public void destroy() {
        this.b = null;
    }

    @Override // com.pubmatic.sdk.openwrap.core.e
    public void requestAd(com.pubmatic.sdk.openwrap.core.f fVar) {
        String str;
        List<f.b> summary;
        f.b bVar;
        if (this.b != null) {
            if (fVar != null && fVar.getStatus() == 1) {
                this.b.onOpenWrapPartnerWin(fVar.getId());
                return;
            }
            if (fVar == null || (summary = fVar.getSummary()) == null || summary.size() <= 0 || (bVar = summary.get(0)) == null) {
                str = null;
            } else {
                str = "OpenWrap error code " + bVar.getErrorCode() + " - " + bVar.getErrorMessage();
            }
            if (str == null) {
                str = "No Ads available for this request";
            }
            this.b.onFailed(new h(1002, str));
        }
    }

    @Override // com.pubmatic.sdk.openwrap.banner.a
    public com.pubmatic.sdk.common.f[] requestedAdSizes() {
        com.pubmatic.sdk.common.f[] fVarArr = this.a;
        if (fVarArr != null) {
            return (com.pubmatic.sdk.common.f[]) Arrays.copyOf(fVarArr, fVarArr.length);
        }
        return null;
    }

    @Override // com.pubmatic.sdk.openwrap.banner.a
    public void setEventListener(@NonNull b bVar) {
        this.b = bVar;
    }

    public e() {
    }
}
