package com.google.android.gms.measurement.internal;

import android.os.Bundle;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.EnumMap;
import java.util.Objects;

/* renamed from: com.google.android.gms.measurement.internal.l, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3878l {
    public static final C3878l f = new C3878l((Boolean) null, 100, (Boolean) null, (String) null);
    public final int a;
    public final String b;
    public final Boolean c;
    public final String d;
    public final EnumMap e;

    public C3878l(Boolean bool, int i, Boolean bool2, String str) {
        EnumMap enumMap = new EnumMap(EnumC3879l0.class);
        this.e = enumMap;
        enumMap.put((EnumMap) EnumC3879l0.AD_USER_DATA, (EnumC3879l0) (bool == null ? EnumC3875j0.UNINITIALIZED : bool.booleanValue() ? EnumC3875j0.GRANTED : EnumC3875j0.DENIED));
        this.a = i;
        this.b = e();
        this.c = bool2;
        this.d = str;
    }

    public static C3878l a(int i, Bundle bundle) {
        if (bundle == null) {
            return new C3878l((Boolean) null, i, (Boolean) null, (String) null);
        }
        EnumMap enumMap = new EnumMap(EnumC3879l0.class);
        for (EnumC3879l0 enumC3879l0 : EnumC3877k0.DMA.a) {
            enumMap.put((EnumMap) enumC3879l0, (EnumC3879l0) C3881m0.b(bundle.getString(enumC3879l0.a)));
        }
        return new C3878l(enumMap, i, bundle.containsKey("is_dma_region") ? Boolean.valueOf(bundle.getString("is_dma_region")) : null, bundle.getString("cps_display_str"));
    }

    public static C3878l b(String str) throws NumberFormatException {
        if (str == null || str.length() <= 0) {
            return f;
        }
        String[] strArrSplit = str.split(":");
        int i = Integer.parseInt(strArrSplit[0]);
        EnumMap enumMap = new EnumMap(EnumC3879l0.class);
        EnumC3879l0[] enumC3879l0Arr = EnumC3877k0.DMA.a;
        int length = enumC3879l0Arr.length;
        int i2 = 1;
        int i3 = 0;
        while (i3 < length) {
            enumMap.put((EnumMap) enumC3879l0Arr[i3], (EnumC3879l0) C3881m0.c(strArrSplit[i2].charAt(0)));
            i3++;
            i2++;
        }
        return new C3878l(enumMap, i, (Boolean) null, (String) null);
    }

    public static Boolean d(Bundle bundle) {
        if (bundle == null) {
            return null;
        }
        int iOrdinal = C3881m0.b(bundle.getString("ad_personalization")).ordinal();
        if (iOrdinal == 2) {
            return Boolean.FALSE;
        }
        if (iOrdinal != 3) {
            return null;
        }
        return Boolean.TRUE;
    }

    public final EnumC3875j0 c() {
        EnumC3875j0 enumC3875j0 = (EnumC3875j0) this.e.get(EnumC3879l0.AD_USER_DATA);
        return enumC3875j0 == null ? EnumC3875j0.UNINITIALIZED : enumC3875j0;
    }

    public final String e() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.a);
        for (EnumC3879l0 enumC3879l0 : EnumC3877k0.DMA.a) {
            sb.append(":");
            sb.append(C3881m0.a((EnumC3875j0) this.e.get(enumC3879l0)));
        }
        return sb.toString();
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C3878l)) {
            return false;
        }
        C3878l c3878l = (C3878l) obj;
        if (this.b.equalsIgnoreCase(c3878l.b) && Objects.equals(this.c, c3878l.c)) {
            return Objects.equals(this.d, c3878l.d);
        }
        return false;
    }

    public final int hashCode() {
        Boolean bool = this.c;
        int i = bool == null ? 3 : true != bool.booleanValue() ? 13 : 7;
        String str = this.d;
        return ((str == null ? 17 : str.hashCode()) * 137) + this.b.hashCode() + (i * 29);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("source=");
        sb.append(C3881m0.h(this.a));
        for (EnumC3879l0 enumC3879l0 : EnumC3877k0.DMA.a) {
            sb.append(",");
            sb.append(enumC3879l0.a);
            sb.append(SimpleComparison.EQUAL_TO_OPERATION);
            EnumC3875j0 enumC3875j0 = (EnumC3875j0) this.e.get(enumC3879l0);
            if (enumC3875j0 == null) {
                sb.append("uninitialized");
            } else {
                int iOrdinal = enumC3875j0.ordinal();
                if (iOrdinal == 0) {
                    sb.append("uninitialized");
                } else if (iOrdinal == 1) {
                    sb.append("eu_consent_policy");
                } else if (iOrdinal == 2) {
                    sb.append("denied");
                } else if (iOrdinal == 3) {
                    sb.append("granted");
                }
            }
        }
        Boolean bool = this.c;
        if (bool != null) {
            sb.append(",isDmaRegion=");
            sb.append(bool);
        }
        String str = this.d;
        if (str != null) {
            sb.append(",cpsDisplayStr=");
            sb.append(str);
        }
        return sb.toString();
    }

    public C3878l(EnumMap enumMap, int i, Boolean bool, String str) {
        EnumMap enumMap2 = new EnumMap(EnumC3879l0.class);
        this.e = enumMap2;
        enumMap2.putAll(enumMap);
        this.a = i;
        this.b = e();
        this.c = bool;
        this.d = str;
    }
}
