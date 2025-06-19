package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.ads.mediation.admob.AdMobAdapter;
import com.google.android.gms.ads.mediation.customevent.CustomEventAdapter;
import com.google.android.gms.ads.mediation.rtb.RtbAdapter;

/* renamed from: com.google.android.gms.internal.ads.va, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2739va extends AbstractBinderC2814x5 implements InterfaceC2825xa {
    public BinderC2739va() {
        super("com.google.android.gms.ads.internal.mediation.client.IAdapterCreator");
    }

    public static InterfaceC2825xa e4(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IAdapterCreator");
        return iInterfaceQueryLocalInterface instanceof InterfaceC2825xa ? (InterfaceC2825xa) iInterfaceQueryLocalInterface : new C2782wa(iBinder, "com.google.android.gms.ads.internal.mediation.client.IAdapterCreator", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2825xa
    public final InterfaceC1965db A(String str) {
        return new BinderC2140hb((RtbAdapter) Class.forName(str, false, AbstractC2096gb.class.getClassLoader()).getDeclaredConstructor(null).newInstance(null));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2825xa
    public final InterfaceC2911za C(String str) throws RemoteException {
        try {
            try {
                Class<?> cls = Class.forName(str, false, BinderC2739va.class.getClassLoader());
                if (com.google.android.gms.ads.mediation.e.class.isAssignableFrom(cls)) {
                    return new BinderC1737Na((com.google.android.gms.ads.mediation.e) cls.getDeclaredConstructor(null).newInstance(null));
                }
                if (com.google.android.gms.ads.mediation.a.class.isAssignableFrom(cls)) {
                    return new BinderC1737Na((com.google.android.gms.ads.mediation.a) cls.getDeclaredConstructor(null).newInstance(null));
                }
                com.google.android.gms.ads.internal.util.client.i.h("Could not instantiate mediation adapter: " + str + " (not a valid adapter).");
                throw new RemoteException();
            } catch (Throwable th) {
                com.google.android.gms.ads.internal.util.client.i.i("Could not instantiate mediation adapter: " + str + ". ", th);
                throw new RemoteException();
            }
        } catch (Throwable unused) {
            com.google.android.gms.ads.internal.util.client.i.d("Reflection failed, retrying using direct instantiation");
            if ("com.google.ads.mediation.admob.AdMobAdapter".equals(str)) {
                return new BinderC1737Na(new AdMobAdapter());
            }
            if ("com.google.android.gms.ads.mediation.customevent.CustomEventAdapter".equals(str)) {
                return new BinderC1737Na(new CustomEventAdapter());
            }
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2825xa
    public final boolean I(String str) {
        try {
            return com.google.android.gms.ads.mediation.a.class.isAssignableFrom(Class.forName(str, false, BinderC2739va.class.getClassLoader()));
        } catch (Throwable unused) {
            com.google.android.gms.ads.internal.util.client.i.h("Could not load custom event implementation class as Adapter: " + str + ", assuming old custom event implementation.");
            return false;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2825xa
    public final boolean R(String str) {
        try {
            return com.google.android.gms.ads.mediation.customevent.a.class.isAssignableFrom(Class.forName(str, false, BinderC2739va.class.getClassLoader()));
        } catch (Throwable unused) {
            com.google.android.gms.ads.internal.util.client.i.h("Could not load custom event implementation class: " + str + ", trying Adapter implementation class.");
            return false;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) throws RemoteException {
        if (i == 1) {
            String string = parcel.readString();
            AbstractC2857y5.b(parcel);
            InterfaceC2911za interfaceC2911zaC = C(string);
            parcel2.writeNoException();
            AbstractC2857y5.e(parcel2, interfaceC2911zaC);
            return true;
        }
        if (i == 2) {
            String string2 = parcel.readString();
            AbstractC2857y5.b(parcel);
            boolean zR = R(string2);
            parcel2.writeNoException();
            parcel2.writeInt(zR ? 1 : 0);
            return true;
        }
        if (i == 3) {
            String string3 = parcel.readString();
            AbstractC2857y5.b(parcel);
            InterfaceC1965db interfaceC1965dbA = A(string3);
            parcel2.writeNoException();
            AbstractC2857y5.e(parcel2, interfaceC1965dbA);
            return true;
        }
        if (i != 4) {
            return false;
        }
        String string4 = parcel.readString();
        AbstractC2857y5.b(parcel);
        boolean zI = I(string4);
        parcel2.writeNoException();
        parcel2.writeInt(zI ? 1 : 0);
        return true;
    }
}
