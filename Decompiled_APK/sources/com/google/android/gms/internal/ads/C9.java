package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.os.Bundle;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import com.google.android.gms.internal.measurement.C2963a0;
import com.google.android.gms.internal.measurement.C2978d0;
import com.google.android.gms.internal.measurement.C2983e0;
import com.google.android.gms.internal.measurement.C3008j0;
import com.google.android.gms.internal.measurement.zzdj;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public final class C9 extends AbstractBinderC2814x5 {
    public final /* synthetic */ int a = 1;
    public final Object b;

    public C9(androidx.appcompat.app.Q q) {
        super("com.google.android.gms.ads.measurement.IAppMeasurementProxy");
        this.b = q;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                if (i != 1) {
                    return false;
                }
                ParcelFileDescriptor parcelFileDescriptor = (ParcelFileDescriptor) AbstractC2857y5.a(parcel, ParcelFileDescriptor.CREATOR);
                AbstractC2857y5.b(parcel);
                ((C2313ld) obj).c(parcelFileDescriptor);
                return true;
            default:
                androidx.appcompat.app.Q q = (androidx.appcompat.app.Q) obj;
                switch (i) {
                    case 1:
                        Bundle bundle = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                        AbstractC2857y5.b(parcel);
                        C3008j0 c3008j0 = (C3008j0) q.a;
                        c3008j0.getClass();
                        c3008j0.c(new C2978d0(c3008j0, bundle, new com.google.android.gms.internal.measurement.G(), 0));
                        parcel2.writeNoException();
                        return true;
                    case 2:
                        Bundle bundle2 = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                        AbstractC2857y5.b(parcel);
                        C3008j0 c3008j02 = (C3008j0) q.a;
                        c3008j02.getClass();
                        com.google.android.gms.internal.measurement.G g = new com.google.android.gms.internal.measurement.G();
                        c3008j02.c(new C2978d0(c3008j02, bundle2, g, 0));
                        Bundle bundleX = g.X(5000L);
                        parcel2.writeNoException();
                        AbstractC2857y5.d(parcel2, bundleX);
                        return true;
                    case 3:
                        String string = parcel.readString();
                        String string2 = parcel.readString();
                        Bundle bundle3 = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                        AbstractC2857y5.b(parcel);
                        C3008j0 c3008j03 = (C3008j0) q.a;
                        c3008j03.getClass();
                        c3008j03.c(new C2983e0(c3008j03, null, string, string2, bundle3, true, true));
                        parcel2.writeNoException();
                        return true;
                    case 4:
                        String string3 = parcel.readString();
                        String string4 = parcel.readString();
                        com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                        AbstractC2857y5.b(parcel);
                        Object objI3 = aVarV3 != null ? com.google.android.gms.dynamic.b.I3(aVarV3) : null;
                        C3008j0 c3008j04 = (C3008j0) q.a;
                        c3008j04.getClass();
                        c3008j04.c(new com.google.android.gms.internal.measurement.U(c3008j04, string3, string4, objI3, 0));
                        parcel2.writeNoException();
                        return true;
                    case 5:
                        String string5 = parcel.readString();
                        String string6 = parcel.readString();
                        ClassLoader classLoader = AbstractC2857y5.a;
                        boolean z = parcel.readInt() != 0;
                        AbstractC2857y5.b(parcel);
                        Map mapH = ((C3008j0) q.a).h(string5, string6, z);
                        parcel2.writeNoException();
                        parcel2.writeMap(mapH);
                        return true;
                    case 6:
                        String string7 = parcel.readString();
                        AbstractC2857y5.b(parcel);
                        int iD = ((C3008j0) q.a).d(string7);
                        parcel2.writeNoException();
                        parcel2.writeInt(iD);
                        return true;
                    case 7:
                        Bundle bundle4 = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                        AbstractC2857y5.b(parcel);
                        C3008j0 c3008j05 = (C3008j0) q.a;
                        c3008j05.getClass();
                        c3008j05.c(new com.google.android.gms.internal.measurement.V(c3008j05, bundle4, 0));
                        parcel2.writeNoException();
                        return true;
                    case 8:
                        String string8 = parcel.readString();
                        String string9 = parcel.readString();
                        Bundle bundle5 = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                        AbstractC2857y5.b(parcel);
                        C3008j0 c3008j06 = (C3008j0) q.a;
                        c3008j06.getClass();
                        c3008j06.c(new com.google.android.gms.internal.measurement.U(c3008j06, string8, string9, bundle5, 1));
                        parcel2.writeNoException();
                        return true;
                    case 9:
                        String string10 = parcel.readString();
                        String string11 = parcel.readString();
                        AbstractC2857y5.b(parcel);
                        List listG = ((C3008j0) q.a).g(string10, string11);
                        parcel2.writeNoException();
                        parcel2.writeList(listG);
                        return true;
                    case 10:
                        C3008j0 c3008j07 = (C3008j0) q.a;
                        c3008j07.getClass();
                        com.google.android.gms.internal.measurement.G g2 = new com.google.android.gms.internal.measurement.G();
                        c3008j07.c(new C2963a0(c3008j07, g2, 1));
                        String str = (String) com.google.android.gms.internal.measurement.G.f0(String.class, g2.X(50L));
                        parcel2.writeNoException();
                        parcel2.writeString(str);
                        return true;
                    case 11:
                        C3008j0 c3008j08 = (C3008j0) q.a;
                        c3008j08.getClass();
                        com.google.android.gms.internal.measurement.G g3 = new com.google.android.gms.internal.measurement.G();
                        c3008j08.c(new C2963a0(c3008j08, g3, 0));
                        String str2 = (String) com.google.android.gms.internal.measurement.G.f0(String.class, g3.X(500L));
                        parcel2.writeNoException();
                        parcel2.writeString(str2);
                        return true;
                    case 12:
                        long jE = ((C3008j0) q.a).e();
                        parcel2.writeNoException();
                        parcel2.writeLong(jE);
                        return true;
                    case 13:
                        String string12 = parcel.readString();
                        AbstractC2857y5.b(parcel);
                        C3008j0 c3008j09 = (C3008j0) q.a;
                        c3008j09.getClass();
                        c3008j09.c(new com.google.android.gms.internal.measurement.W(c3008j09, string12, 1));
                        parcel2.writeNoException();
                        return true;
                    case 14:
                        String string13 = parcel.readString();
                        AbstractC2857y5.b(parcel);
                        C3008j0 c3008j010 = (C3008j0) q.a;
                        c3008j010.getClass();
                        c3008j010.c(new com.google.android.gms.internal.measurement.W(c3008j010, string13, 2));
                        parcel2.writeNoException();
                        return true;
                    case 15:
                        com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                        String string14 = parcel.readString();
                        String string15 = parcel.readString();
                        AbstractC2857y5.b(parcel);
                        Activity activity = aVarV32 != null ? (Activity) com.google.android.gms.dynamic.b.I3(aVarV32) : null;
                        q.getClass();
                        zzdj zzdjVarA = zzdj.a(activity);
                        C3008j0 c3008j011 = (C3008j0) q.a;
                        c3008j011.getClass();
                        c3008j011.c(new com.google.android.gms.internal.measurement.U(c3008j011, zzdjVarA, string14, string15));
                        parcel2.writeNoException();
                        return true;
                    case 16:
                        C3008j0 c3008j012 = (C3008j0) q.a;
                        c3008j012.getClass();
                        com.google.android.gms.internal.measurement.G g4 = new com.google.android.gms.internal.measurement.G();
                        c3008j012.c(new C2963a0(c3008j012, g4, 3));
                        String str3 = (String) com.google.android.gms.internal.measurement.G.f0(String.class, g4.X(500L));
                        parcel2.writeNoException();
                        parcel2.writeString(str3);
                        return true;
                    case 17:
                        C3008j0 c3008j013 = (C3008j0) q.a;
                        c3008j013.getClass();
                        com.google.android.gms.internal.measurement.G g5 = new com.google.android.gms.internal.measurement.G();
                        c3008j013.c(new C2963a0(c3008j013, g5, 4));
                        String str4 = (String) com.google.android.gms.internal.measurement.G.f0(String.class, g5.X(500L));
                        parcel2.writeNoException();
                        parcel2.writeString(str4);
                        return true;
                    case 18:
                        String str5 = ((C3008j0) q.a).h;
                        parcel2.writeNoException();
                        parcel2.writeString(str5);
                        return true;
                    case 19:
                        AbstractC2857y5.b(parcel);
                        q.getClass();
                        parcel2.writeNoException();
                        return true;
                    default:
                        return false;
                }
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C9(C2313ld c2313ld) {
        super("com.google.android.gms.ads.internal.httpcache.IHttpAssetsCacheCallback");
        this.b = c2313ld;
    }
}
