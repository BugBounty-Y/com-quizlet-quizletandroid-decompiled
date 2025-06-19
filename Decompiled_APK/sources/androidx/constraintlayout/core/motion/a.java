package androidx.constraintlayout.core.motion;

import androidx.compose.animation.d0;
import com.comscore.streaming.ContentDistributionModel;

/* loaded from: classes.dex */
public final class a {
    public String a;
    public int b;
    public int c;
    public float d;

    public final String toString() {
        String strR = d0.r(new StringBuilder(), this.a, ':');
        switch (this.b) {
            case com.pubmatic.sdk.video.a.UNDEFINED_ERROR /* 900 */:
                StringBuilder sbU = d0.u(strR);
                sbU.append(this.c);
                return sbU.toString();
            case ContentDistributionModel.TV_AND_ONLINE /* 901 */:
                StringBuilder sbU2 = d0.u(strR);
                sbU2.append(this.d);
                return sbU2.toString();
            case ContentDistributionModel.EXCLUSIVELY_ONLINE /* 902 */:
                StringBuilder sbU3 = d0.u(strR);
                sbU3.append("#" + ("00000000" + Integer.toHexString(this.c)).substring(r1.length() - 8));
                return sbU3.toString();
            case 903:
                return android.support.v4.media.session.a.k(strR, null);
            default:
                return android.support.v4.media.session.a.k(strR, "????");
        }
    }
}
