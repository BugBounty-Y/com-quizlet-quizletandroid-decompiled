package androidx.room;

import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class o extends Binder implements j {
    public final /* synthetic */ MultiInstanceInvalidationService a;

    public o(MultiInstanceInvalidationService multiInstanceInvalidationService) {
        this.a = multiInstanceInvalidationService;
        attachInterface(this, j.F0);
    }

    @Override // android.os.IInterface
    public final IBinder asBinder() {
        return this;
    }

    @Override // android.os.Binder
    public final boolean onTransact(int i, Parcel parcel, Parcel parcel2, int i2) {
        int i3 = 0;
        String str = j.F0;
        if (i >= 1 && i <= 16777215) {
            parcel.enforceInterface(str);
        }
        if (i == 1598968902) {
            parcel2.writeString(str);
            return true;
        }
        i callback = null;
        i callback2 = null;
        if (i == 1) {
            IBinder strongBinder = parcel.readStrongBinder();
            if (strongBinder != null) {
                IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface(i.E0);
                if (iInterfaceQueryLocalInterface == null || !(iInterfaceQueryLocalInterface instanceof i)) {
                    h hVar = new h();
                    hVar.a = strongBinder;
                    callback = hVar;
                } else {
                    callback = (i) iInterfaceQueryLocalInterface;
                }
            }
            String string = parcel.readString();
            Intrinsics.checkNotNullParameter(callback, "callback");
            if (string != null) {
                MultiInstanceInvalidationService multiInstanceInvalidationService = this.a;
                synchronized (multiInstanceInvalidationService.c) {
                    try {
                        int i4 = multiInstanceInvalidationService.a + 1;
                        multiInstanceInvalidationService.a = i4;
                        if (multiInstanceInvalidationService.c.register(callback, Integer.valueOf(i4))) {
                            multiInstanceInvalidationService.b.put(Integer.valueOf(i4), string);
                            i3 = i4;
                        } else {
                            multiInstanceInvalidationService.a--;
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            }
            parcel2.writeNoException();
            parcel2.writeInt(i3);
            return true;
        }
        if (i == 2) {
            IBinder strongBinder2 = parcel.readStrongBinder();
            if (strongBinder2 != null) {
                IInterface iInterfaceQueryLocalInterface2 = strongBinder2.queryLocalInterface(i.E0);
                if (iInterfaceQueryLocalInterface2 == null || !(iInterfaceQueryLocalInterface2 instanceof i)) {
                    h hVar2 = new h();
                    hVar2.a = strongBinder2;
                    callback2 = hVar2;
                } else {
                    callback2 = (i) iInterfaceQueryLocalInterface2;
                }
            }
            int i5 = parcel.readInt();
            Intrinsics.checkNotNullParameter(callback2, "callback");
            MultiInstanceInvalidationService multiInstanceInvalidationService2 = this.a;
            synchronized (multiInstanceInvalidationService2.c) {
                multiInstanceInvalidationService2.c.unregister(callback2);
            }
            parcel2.writeNoException();
            return true;
        }
        if (i != 3) {
            return super.onTransact(i, parcel, parcel2, i2);
        }
        int i6 = parcel.readInt();
        String[] tables = parcel.createStringArray();
        Intrinsics.checkNotNullParameter(tables, "tables");
        MultiInstanceInvalidationService multiInstanceInvalidationService3 = this.a;
        synchronized (multiInstanceInvalidationService3.c) {
            String str2 = (String) multiInstanceInvalidationService3.b.get(Integer.valueOf(i6));
            if (str2 == null) {
                Log.w("ROOM", "Remote invalidation client ID not registered");
            } else {
                int iBeginBroadcast = multiInstanceInvalidationService3.c.beginBroadcast();
                while (i3 < iBeginBroadcast) {
                    try {
                        Object broadcastCookie = multiInstanceInvalidationService3.c.getBroadcastCookie(i3);
                        Intrinsics.e(broadcastCookie, "null cannot be cast to non-null type kotlin.Int");
                        Integer num = (Integer) broadcastCookie;
                        int iIntValue = num.intValue();
                        String str3 = (String) multiInstanceInvalidationService3.b.get(num);
                        if (i6 != iIntValue && str2.equals(str3)) {
                            try {
                                ((i) multiInstanceInvalidationService3.c.getBroadcastItem(i3)).T0(tables);
                            } catch (RemoteException e) {
                                Log.w("ROOM", "Error invoking a remote callback", e);
                            }
                        }
                        i3++;
                    } catch (Throwable th2) {
                        multiInstanceInvalidationService3.c.finishBroadcast();
                        throw th2;
                    }
                }
                multiInstanceInvalidationService3.c.finishBroadcast();
                Unit unit = Unit.a;
            }
        }
        return true;
    }
}
