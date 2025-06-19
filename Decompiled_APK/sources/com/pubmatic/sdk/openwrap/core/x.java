package com.pubmatic.sdk.openwrap.core;

import androidx.annotation.NonNull;
import java.util.Objects;

/* loaded from: classes2.dex */
public class x implements com.pubmatic.sdk.common.ui.b {
    public static final int DEFAULT_REWARD_AMOUNT_VALUE = 0;
    public static final String DEFAULT_REWARD_TYPE_LABEL = "";

    @NonNull
    private final String a;
    private final int b;

    public x(@NonNull String str, int i) {
        this.a = str;
        this.b = i;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && getClass() == obj.getClass()) {
            x xVar = (x) obj;
            if (this.b == xVar.b && this.a.equals(xVar.a)) {
                return true;
            }
        }
        return false;
    }

    @Override // com.pubmatic.sdk.common.ui.b
    public int getAmount() {
        return this.b;
    }

    @Override // com.pubmatic.sdk.common.ui.b
    @NonNull
    public String getCurrencyType() {
        return this.a;
    }

    public int hashCode() {
        return Objects.hash(this.a, Integer.valueOf(this.b));
    }

    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder("POBReward{currencyType='");
        sb.append(this.a);
        sb.append("', amount='");
        return android.support.v4.media.session.a.r(sb, this.b, "'}");
    }
}
