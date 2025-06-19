package com.google.android.datatransport.cct.internal;

/* loaded from: classes2.dex */
public final class l extends AbstractC1571a {
    public final Integer a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;
    public final String i;
    public final String j;
    public final String k;
    public final String l;

    public l(Integer num, String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, String str10, String str11) {
        this.a = num;
        this.b = str;
        this.c = str2;
        this.d = str3;
        this.e = str4;
        this.f = str5;
        this.g = str6;
        this.h = str7;
        this.i = str8;
        this.j = str9;
        this.k = str10;
        this.l = str11;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof AbstractC1571a) {
            AbstractC1571a abstractC1571a = (AbstractC1571a) obj;
            Integer num = this.a;
            if (num != null ? num.equals(((l) abstractC1571a).a) : ((l) abstractC1571a).a == null) {
                String str = this.b;
                if (str != null ? str.equals(((l) abstractC1571a).b) : ((l) abstractC1571a).b == null) {
                    String str2 = this.c;
                    if (str2 != null ? str2.equals(((l) abstractC1571a).c) : ((l) abstractC1571a).c == null) {
                        String str3 = this.d;
                        if (str3 != null ? str3.equals(((l) abstractC1571a).d) : ((l) abstractC1571a).d == null) {
                            String str4 = this.e;
                            if (str4 != null ? str4.equals(((l) abstractC1571a).e) : ((l) abstractC1571a).e == null) {
                                String str5 = this.f;
                                if (str5 != null ? str5.equals(((l) abstractC1571a).f) : ((l) abstractC1571a).f == null) {
                                    String str6 = this.g;
                                    if (str6 != null ? str6.equals(((l) abstractC1571a).g) : ((l) abstractC1571a).g == null) {
                                        String str7 = this.h;
                                        if (str7 != null ? str7.equals(((l) abstractC1571a).h) : ((l) abstractC1571a).h == null) {
                                            String str8 = this.i;
                                            if (str8 != null ? str8.equals(((l) abstractC1571a).i) : ((l) abstractC1571a).i == null) {
                                                String str9 = this.j;
                                                if (str9 != null ? str9.equals(((l) abstractC1571a).j) : ((l) abstractC1571a).j == null) {
                                                    String str10 = this.k;
                                                    if (str10 != null ? str10.equals(((l) abstractC1571a).k) : ((l) abstractC1571a).k == null) {
                                                        String str11 = this.l;
                                                        if (str11 != null ? str11.equals(((l) abstractC1571a).l) : ((l) abstractC1571a).l == null) {
                                                            return true;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        Integer num = this.a;
        int iHashCode = ((num == null ? 0 : num.hashCode()) ^ 1000003) * 1000003;
        String str = this.b;
        int iHashCode2 = (iHashCode ^ (str == null ? 0 : str.hashCode())) * 1000003;
        String str2 = this.c;
        int iHashCode3 = (iHashCode2 ^ (str2 == null ? 0 : str2.hashCode())) * 1000003;
        String str3 = this.d;
        int iHashCode4 = (iHashCode3 ^ (str3 == null ? 0 : str3.hashCode())) * 1000003;
        String str4 = this.e;
        int iHashCode5 = (iHashCode4 ^ (str4 == null ? 0 : str4.hashCode())) * 1000003;
        String str5 = this.f;
        int iHashCode6 = (iHashCode5 ^ (str5 == null ? 0 : str5.hashCode())) * 1000003;
        String str6 = this.g;
        int iHashCode7 = (iHashCode6 ^ (str6 == null ? 0 : str6.hashCode())) * 1000003;
        String str7 = this.h;
        int iHashCode8 = (iHashCode7 ^ (str7 == null ? 0 : str7.hashCode())) * 1000003;
        String str8 = this.i;
        int iHashCode9 = (iHashCode8 ^ (str8 == null ? 0 : str8.hashCode())) * 1000003;
        String str9 = this.j;
        int iHashCode10 = (iHashCode9 ^ (str9 == null ? 0 : str9.hashCode())) * 1000003;
        String str10 = this.k;
        int iHashCode11 = (iHashCode10 ^ (str10 == null ? 0 : str10.hashCode())) * 1000003;
        String str11 = this.l;
        return (str11 != null ? str11.hashCode() : 0) ^ iHashCode11;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AndroidClientInfo{sdkVersion=");
        sb.append(this.a);
        sb.append(", model=");
        sb.append(this.b);
        sb.append(", hardware=");
        sb.append(this.c);
        sb.append(", device=");
        sb.append(this.d);
        sb.append(", product=");
        sb.append(this.e);
        sb.append(", osBuild=");
        sb.append(this.f);
        sb.append(", manufacturer=");
        sb.append(this.g);
        sb.append(", fingerprint=");
        sb.append(this.h);
        sb.append(", locale=");
        sb.append(this.i);
        sb.append(", country=");
        sb.append(this.j);
        sb.append(", mccMnc=");
        sb.append(this.k);
        sb.append(", applicationBuild=");
        return android.support.v4.media.session.a.t(sb, this.l, "}");
    }
}
