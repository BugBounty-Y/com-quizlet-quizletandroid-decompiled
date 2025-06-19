package com.quizlet.upgrade.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class D {
    public final com.quizlet.qutils.string.d a;
    public final com.quizlet.qutils.string.d b;
    public final com.quizlet.qutils.string.b c;
    public final com.quizlet.qutils.string.f d;

    public D(com.quizlet.qutils.string.d header, com.quizlet.qutils.string.d todayBulletInfo, com.quizlet.qutils.string.b endBulletSubHeader, com.quizlet.qutils.string.f endBulletInfo) {
        Intrinsics.checkNotNullParameter(header, "header");
        Intrinsics.checkNotNullParameter(todayBulletInfo, "todayBulletInfo");
        Intrinsics.checkNotNullParameter(endBulletSubHeader, "endBulletSubHeader");
        Intrinsics.checkNotNullParameter(endBulletInfo, "endBulletInfo");
        this.a = header;
        this.b = todayBulletInfo;
        this.c = endBulletSubHeader;
        this.d = endBulletInfo;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof D)) {
            return false;
        }
        D d = (D) obj;
        return this.a.equals(d.a) && this.b.equals(d.b) && this.c.equals(d.c) && this.d.equals(d.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "UpgradeHeaderFreeTrialDetails(header=" + this.a + ", todayBulletInfo=" + this.b + ", endBulletSubHeader=" + this.c + ", endBulletInfo=" + this.d + ")";
    }
}
