package com.quizlet.upgrade.data;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class UpgradePackage implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<UpgradePackage> CREATOR = new com.quizlet.studiablemodels.grading.e(3);
    public static final UpgradePackage c;
    public static final UpgradePackage d;
    public final com.quizlet.billing.subscriptions.j a;
    public final int b;

    static {
        UpgradePackage upgradePackage = new UpgradePackage(com.quizlet.billing.subscriptions.j.b);
        c = upgradePackage;
        UpgradePackage upgradePackage2 = new UpgradePackage(com.quizlet.billing.subscriptions.j.c);
        d = upgradePackage2;
        kotlin.collections.A.b(upgradePackage);
        kotlin.collections.A.b(upgradePackage2);
    }

    public UpgradePackage(com.quizlet.billing.subscriptions.j subscriptionPackage) {
        Intrinsics.checkNotNullParameter(subscriptionPackage, "subscriptionPackage");
        this.a = subscriptionPackage;
        if (subscriptionPackage != com.quizlet.billing.subscriptions.j.b) {
            com.quizlet.billing.subscriptions.j jVar = com.quizlet.billing.subscriptions.j.d;
        }
        com.quizlet.billing.subscriptions.j jVar2 = com.quizlet.billing.subscriptions.j.a;
        com.quizlet.billing.subscriptions.j jVar3 = com.quizlet.billing.subscriptions.j.a;
        int iOrdinal = subscriptionPackage.ordinal();
        if (iOrdinal == 0) {
            throw new IllegalArgumentException("Unknown subscription tier " + subscriptionPackage);
        }
        int i = 2;
        if (iOrdinal != 1 && iOrdinal != 2 && iOrdinal != 3 && iOrdinal != 4) {
            throw new NoWhenBranchMatchedException();
        }
        int iOrdinal2 = subscriptionPackage.ordinal();
        if (iOrdinal2 == 0) {
            throw new IllegalArgumentException("Unknown subscription tier " + subscriptionPackage);
        }
        if (iOrdinal2 != 1 && iOrdinal2 != 2 && iOrdinal2 != 3 && iOrdinal2 != 4) {
            throw new NoWhenBranchMatchedException();
        }
        int iOrdinal3 = subscriptionPackage.ordinal();
        if (iOrdinal3 == 0) {
            throw new IllegalArgumentException("Unknown subscription tier " + subscriptionPackage);
        }
        if (iOrdinal3 != 1 && iOrdinal3 != 2 && iOrdinal3 != 3 && iOrdinal3 != 4) {
            throw new NoWhenBranchMatchedException();
        }
        int iOrdinal4 = subscriptionPackage.ordinal();
        if (iOrdinal4 == 0) {
            throw new IllegalArgumentException("Unknown subscription tier " + subscriptionPackage);
        }
        if (iOrdinal4 == 1 || iOrdinal4 == 2) {
            i = 1;
        } else if (iOrdinal4 != 3) {
            if (iOrdinal4 != 4) {
                throw new NoWhenBranchMatchedException();
            }
            i = 1;
        }
        this.b = i;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof UpgradePackage) && this.a == ((UpgradePackage) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "UpgradePackage(subscriptionPackage=" + this.a + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a.name());
    }
}
