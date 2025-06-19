package com.google.android.exoplayer2;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.ui.node.B;
import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.exoplayer2.drm.b;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.video.ColorInfo;
import java.util.ArrayList;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class Format implements Parcelable {
    public static final Parcelable.Creator<Format> CREATOR = new android.support.v4.media.a(16);
    public final int A;
    public final int B;
    public final int C;
    public final int D;
    public final Class E;
    public int F;
    public final String a;
    public final String b;
    public final String c;
    public final int d;
    public final int e;
    public final int f;
    public final int g;
    public final int h;
    public final String i;
    public final Metadata j;
    public final String k;
    public final String l;
    public final int m;
    public final ArrayList n;
    public final DrmInitData o;
    public final long p;
    public final int q;
    public final int r;
    public final float s;
    public final int t;
    public final float u;
    public final byte[] v;
    public final int w;
    public final ColorInfo x;
    public final int y;
    public final int z;

    public Format(Parcel parcel) {
        this.a = parcel.readString();
        this.b = parcel.readString();
        this.c = parcel.readString();
        this.d = parcel.readInt();
        this.e = parcel.readInt();
        int i = parcel.readInt();
        this.f = i;
        int i2 = parcel.readInt();
        this.g = i2;
        this.h = i2 != -1 ? i2 : i;
        this.i = parcel.readString();
        this.j = (Metadata) parcel.readParcelable(Metadata.class.getClassLoader());
        this.k = parcel.readString();
        this.l = parcel.readString();
        this.m = parcel.readInt();
        int i3 = parcel.readInt();
        this.n = new ArrayList(i3);
        for (int i4 = 0; i4 < i3; i4++) {
            ArrayList arrayList = this.n;
            byte[] bArrCreateByteArray = parcel.createByteArray();
            bArrCreateByteArray.getClass();
            arrayList.add(bArrCreateByteArray);
        }
        DrmInitData drmInitData = (DrmInitData) parcel.readParcelable(DrmInitData.class.getClassLoader());
        this.o = drmInitData;
        this.p = parcel.readLong();
        this.q = parcel.readInt();
        this.r = parcel.readInt();
        this.s = parcel.readFloat();
        this.t = parcel.readInt();
        this.u = parcel.readFloat();
        int i5 = com.google.android.exoplayer2.util.a.a;
        this.v = parcel.readInt() != 0 ? parcel.createByteArray() : null;
        this.w = parcel.readInt();
        this.x = (ColorInfo) parcel.readParcelable(ColorInfo.class.getClassLoader());
        this.y = parcel.readInt();
        this.z = parcel.readInt();
        this.A = parcel.readInt();
        this.B = parcel.readInt();
        this.C = parcel.readInt();
        this.D = parcel.readInt();
        this.E = drmInitData != null ? b.class : null;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        int i;
        if (this == obj) {
            return true;
        }
        if (obj != null && Format.class == obj.getClass()) {
            Format format = (Format) obj;
            int i2 = this.F;
            if ((i2 == 0 || (i = format.F) == 0 || i2 == i) && this.d == format.d && this.e == format.e && this.f == format.f && this.g == format.g && this.m == format.m && this.p == format.p && this.q == format.q && this.r == format.r && this.t == format.t && this.w == format.w && this.y == format.y && this.z == format.z && this.A == format.A && this.B == format.B && this.C == format.C && this.D == format.D && Float.compare(this.s, format.s) == 0 && Float.compare(this.u, format.u) == 0 && com.google.android.exoplayer2.util.a.a(this.E, format.E) && com.google.android.exoplayer2.util.a.a(this.a, format.a) && com.google.android.exoplayer2.util.a.a(this.b, format.b) && com.google.android.exoplayer2.util.a.a(this.i, format.i) && com.google.android.exoplayer2.util.a.a(this.k, format.k) && com.google.android.exoplayer2.util.a.a(this.l, format.l) && com.google.android.exoplayer2.util.a.a(this.c, format.c) && Arrays.equals(this.v, format.v) && com.google.android.exoplayer2.util.a.a(this.j, format.j) && com.google.android.exoplayer2.util.a.a(this.x, format.x) && com.google.android.exoplayer2.util.a.a(this.o, format.o)) {
                ArrayList arrayList = this.n;
                int size = arrayList.size();
                ArrayList arrayList2 = format.n;
                if (size == arrayList2.size()) {
                    for (int i3 = 0; i3 < arrayList.size(); i3++) {
                        if (Arrays.equals((byte[]) arrayList.get(i3), (byte[]) arrayList2.get(i3))) {
                        }
                    }
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        if (this.F == 0) {
            String str = this.a;
            int iHashCode = (527 + (str == null ? 0 : str.hashCode())) * 31;
            String str2 = this.b;
            int iHashCode2 = (iHashCode + (str2 != null ? str2.hashCode() : 0)) * 31;
            String str3 = this.c;
            int iHashCode3 = (((((((((iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31) + this.d) * 31) + this.e) * 31) + this.f) * 31) + this.g) * 31;
            String str4 = this.i;
            int iHashCode4 = (iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31;
            Metadata metadata = this.j;
            int iHashCode5 = (iHashCode4 + (metadata == null ? 0 : Arrays.hashCode(metadata.a))) * 31;
            String str5 = this.k;
            int iHashCode6 = (iHashCode5 + (str5 == null ? 0 : str5.hashCode())) * 31;
            String str6 = this.l;
            int iFloatToIntBits = (((((((((((((((Float.floatToIntBits(this.u) + ((((Float.floatToIntBits(this.s) + ((((((((((iHashCode6 + (str6 == null ? 0 : str6.hashCode())) * 31) + this.m) * 31) + ((int) this.p)) * 31) + this.q) * 31) + this.r) * 31)) * 31) + this.t) * 31)) * 31) + this.w) * 31) + this.y) * 31) + this.z) * 31) + this.A) * 31) + this.B) * 31) + this.C) * 31) + this.D) * 31;
            Class cls = this.E;
            this.F = iFloatToIntBits + (cls != null ? cls.hashCode() : 0);
        }
        return this.F;
    }

    public final String toString() {
        String str = this.a;
        int length = String.valueOf(str).length() + 104;
        String str2 = this.b;
        int length2 = String.valueOf(str2).length() + length;
        String str3 = this.k;
        int length3 = String.valueOf(str3).length() + length2;
        String str4 = this.l;
        int length4 = String.valueOf(str4).length() + length3;
        String str5 = this.i;
        int length5 = String.valueOf(str5).length() + length4;
        String str6 = this.c;
        StringBuilder sb = new StringBuilder(String.valueOf(str6).length() + length5);
        sb.append("Format(");
        sb.append(str);
        sb.append(", ");
        sb.append(str2);
        B.u(sb, ", ", str3, ", ", str4);
        sb.append(", ");
        sb.append(str5);
        sb.append(", ");
        sb.append(this.h);
        sb.append(", ");
        sb.append(str6);
        sb.append(", [");
        sb.append(this.q);
        sb.append(", ");
        sb.append(this.r);
        sb.append(", ");
        sb.append(this.s);
        sb.append("], [");
        sb.append(this.y);
        sb.append(", ");
        return android.support.v4.media.session.a.r(sb, this.z, "])");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(this.a);
        parcel.writeString(this.b);
        parcel.writeString(this.c);
        parcel.writeInt(this.d);
        parcel.writeInt(this.e);
        parcel.writeInt(this.f);
        parcel.writeInt(this.g);
        parcel.writeString(this.i);
        parcel.writeParcelable(this.j, 0);
        parcel.writeString(this.k);
        parcel.writeString(this.l);
        parcel.writeInt(this.m);
        ArrayList arrayList = this.n;
        int size = arrayList.size();
        parcel.writeInt(size);
        for (int i2 = 0; i2 < size; i2++) {
            parcel.writeByteArray((byte[]) arrayList.get(i2));
        }
        parcel.writeParcelable(this.o, 0);
        parcel.writeLong(this.p);
        parcel.writeInt(this.q);
        parcel.writeInt(this.r);
        parcel.writeFloat(this.s);
        parcel.writeInt(this.t);
        parcel.writeFloat(this.u);
        byte[] bArr = this.v;
        int i3 = bArr == null ? 0 : 1;
        int i4 = com.google.android.exoplayer2.util.a.a;
        parcel.writeInt(i3);
        if (bArr != null) {
            parcel.writeByteArray(bArr);
        }
        parcel.writeInt(this.w);
        parcel.writeParcelable(this.x, i);
        parcel.writeInt(this.y);
        parcel.writeInt(this.z);
        parcel.writeInt(this.A);
        parcel.writeInt(this.B);
        parcel.writeInt(this.C);
        parcel.writeInt(this.D);
    }
}
