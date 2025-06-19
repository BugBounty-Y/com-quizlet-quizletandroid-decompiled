package com.appsflyer;

import androidx.compose.ui.node.B;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AFPurchaseDetails {

    @NotNull
    private final String currency;

    @NotNull
    private final String price;

    @NotNull
    private final String productId;

    @NotNull
    private final String purchaseToken;

    @NotNull
    private final AFPurchaseType purchaseType;

    public AFPurchaseDetails(@NotNull AFPurchaseType aFPurchaseType, @NotNull String str, @NotNull String str2, @NotNull String str3, @NotNull String str4) {
        Intrinsics.checkNotNullParameter(aFPurchaseType, "");
        Intrinsics.checkNotNullParameter(str, "");
        Intrinsics.checkNotNullParameter(str2, "");
        Intrinsics.checkNotNullParameter(str3, "");
        Intrinsics.checkNotNullParameter(str4, "");
        this.purchaseType = aFPurchaseType;
        this.purchaseToken = str;
        this.productId = str2;
        this.price = str3;
        this.currency = str4;
    }

    public static /* synthetic */ AFPurchaseDetails copy$default(AFPurchaseDetails aFPurchaseDetails, AFPurchaseType aFPurchaseType, String str, String str2, String str3, String str4, int i, Object obj) {
        if ((i & 1) != 0) {
            aFPurchaseType = aFPurchaseDetails.purchaseType;
        }
        if ((i & 2) != 0) {
            str = aFPurchaseDetails.purchaseToken;
        }
        if ((i & 4) != 0) {
            str2 = aFPurchaseDetails.productId;
        }
        if ((i & 8) != 0) {
            str3 = aFPurchaseDetails.price;
        }
        if ((i & 16) != 0) {
            str4 = aFPurchaseDetails.currency;
        }
        String str5 = str4;
        String str6 = str2;
        return aFPurchaseDetails.copy(aFPurchaseType, str, str6, str3, str5);
    }

    @NotNull
    public final AFPurchaseType component1() {
        return this.purchaseType;
    }

    @NotNull
    public final String component2() {
        return this.purchaseToken;
    }

    @NotNull
    public final String component3() {
        return this.productId;
    }

    @NotNull
    public final String component4() {
        return this.price;
    }

    @NotNull
    public final String component5() {
        return this.currency;
    }

    @NotNull
    public final AFPurchaseDetails copy(@NotNull AFPurchaseType aFPurchaseType, @NotNull String str, @NotNull String str2, @NotNull String str3, @NotNull String str4) {
        Intrinsics.checkNotNullParameter(aFPurchaseType, "");
        Intrinsics.checkNotNullParameter(str, "");
        Intrinsics.checkNotNullParameter(str2, "");
        Intrinsics.checkNotNullParameter(str3, "");
        Intrinsics.checkNotNullParameter(str4, "");
        return new AFPurchaseDetails(aFPurchaseType, str, str2, str3, str4);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AFPurchaseDetails)) {
            return false;
        }
        AFPurchaseDetails aFPurchaseDetails = (AFPurchaseDetails) obj;
        return this.purchaseType == aFPurchaseDetails.purchaseType && Intrinsics.b(this.purchaseToken, aFPurchaseDetails.purchaseToken) && Intrinsics.b(this.productId, aFPurchaseDetails.productId) && Intrinsics.b(this.price, aFPurchaseDetails.price) && Intrinsics.b(this.currency, aFPurchaseDetails.currency);
    }

    @NotNull
    public final String getCurrency() {
        return this.currency;
    }

    @NotNull
    public final String getPrice() {
        return this.price;
    }

    @NotNull
    public final String getProductId() {
        return this.productId;
    }

    @NotNull
    public final String getPurchaseToken() {
        return this.purchaseToken;
    }

    @NotNull
    public final AFPurchaseType getPurchaseType() {
        return this.purchaseType;
    }

    public final int hashCode() {
        return this.currency.hashCode() + ((this.price.hashCode() + ((this.productId.hashCode() + ((this.purchaseToken.hashCode() + (this.purchaseType.hashCode() * 31)) * 31)) * 31)) * 31);
    }

    @NotNull
    public final String toString() {
        AFPurchaseType aFPurchaseType = this.purchaseType;
        String str = this.purchaseToken;
        String str2 = this.productId;
        String str3 = this.price;
        String str4 = this.currency;
        StringBuilder sb = new StringBuilder("AFPurchaseDetails(purchaseType=");
        sb.append(aFPurchaseType);
        sb.append(", purchaseToken=");
        sb.append(str);
        sb.append(", productId=");
        B.u(sb, str2, ", price=", str3, ", currency=");
        return android.support.v4.media.session.a.t(sb, str4, ")");
    }
}
