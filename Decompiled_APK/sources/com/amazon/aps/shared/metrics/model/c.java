package com.amazon.aps.shared.metrics.model;

import com.amazon.device.ads.DtbConstants;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f = DtbConstants.NATIVE_OS_NAME;
    public final String g = "app";

    public c(String str, String str2, String str3, String str4, String str5) {
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = str4;
        this.e = str5;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && Intrinsics.b(this.b, cVar.b) && Intrinsics.b(this.c, cVar.c) && Intrinsics.b(this.d, cVar.d) && Intrinsics.b(this.e, cVar.e);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.c;
        int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.d;
        int iHashCode4 = (iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.e;
        return iHashCode4 + (str5 != null ? str5.hashCode() : 0);
    }

    public final String toString() {
        return "ApsMetricsDeviceInfo(platformCategory=" + ((Object) this.a) + ", screenSize=" + ((Object) this.b) + ", deviceType=" + ((Object) this.c) + ", connectionType=" + ((Object) this.d) + ", platformCategoryVersion=" + ((Object) this.e) + ')';
    }
}
