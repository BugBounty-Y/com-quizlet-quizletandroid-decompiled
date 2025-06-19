package org.prebid.mobile.rendering.utils.exposure;

import android.graphics.Rect;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes3.dex */
public class ViewExposure {
    public float a = DefinitionKt.NO_Float_VALUE;
    public Rect b = new Rect();
    public ArrayList c = null;

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        ViewExposure viewExposure = (ViewExposure) obj;
        if (Float.compare(viewExposure.a, this.a) != 0) {
            return false;
        }
        Rect rect = viewExposure.b;
        Rect rect2 = this.b;
        if (rect2 != null) {
            if (!rect2.equals(rect)) {
                return false;
            }
        } else if (rect != null) {
            return false;
        }
        ArrayList arrayList = viewExposure.c;
        ArrayList arrayList2 = this.c;
        return arrayList2 != null ? arrayList2.equals(arrayList) : arrayList == null;
    }

    public final int hashCode() {
        float f = this.a;
        int iFloatToIntBits = (f != DefinitionKt.NO_Float_VALUE ? Float.floatToIntBits(f) : 0) * 31;
        Rect rect = this.b;
        int iHashCode = (iFloatToIntBits + (rect != null ? rect.hashCode() : 0)) * 31;
        ArrayList arrayList = this.c;
        return iHashCode + (arrayList != null ? arrayList.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("{\"exposedPercentage\":");
        sb.append(this.a * 100.0f);
        sb.append(",\"visibleRectangle\":{\"x\":");
        Rect rect = this.b;
        sb.append(rect.left);
        sb.append(",\"y\":");
        sb.append(rect.top);
        sb.append(",\"width\":");
        sb.append(rect.width());
        sb.append(",\"height\":");
        sb.append(rect.height());
        sb.append("}");
        ArrayList arrayList = this.c;
        if (arrayList != null && !arrayList.isEmpty()) {
            sb.append(", \"occlusionRectangles\":[");
            for (int i = 0; i < arrayList.size(); i++) {
                Rect rect2 = (Rect) arrayList.get(i);
                sb.append("{\"x\":");
                sb.append(rect2.left);
                sb.append(",\"y\":");
                sb.append(rect2.top);
                sb.append(",\"width\":");
                sb.append(rect2.width());
                sb.append(",\"height\":");
                sb.append(rect2.height());
                sb.append("}");
                if (i < arrayList.size() - 1) {
                    sb.append(",");
                }
            }
            sb.append("]");
        }
        sb.append("}");
        return sb.toString();
    }
}
