package org.prebid.mobile.rendering.models.openrtb.bidRequests.imps.pmps;

import org.prebid.mobile.rendering.models.openrtb.bidRequests.BaseBid;

/* loaded from: classes3.dex */
public class Format extends BaseBid {
    public Integer a;
    public Integer b;

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && getClass() == obj.getClass()) {
            Format format = (Format) obj;
            Integer num = format.a;
            Integer num2 = this.a;
            if (num2 == null ? num != null : !num2.equals(num)) {
                return false;
            }
            Integer num3 = format.b;
            Integer num4 = this.b;
            if (num4 != null) {
                return num4.equals(num3);
            }
            if (num3 == null) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        Integer num = this.a;
        int iHashCode = (num != null ? num.hashCode() : 0) * 31;
        Integer num2 = this.b;
        return iHashCode + (num2 != null ? num2.hashCode() : 0);
    }
}
